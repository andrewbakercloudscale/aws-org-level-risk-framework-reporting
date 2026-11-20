"""Security Group Review: who reaches each account's security groups, who is refused, and which allowed
address space is never used, over time, so over-provisioned rules can be taken down safely.

One account at a time, read live with the scan's profile and role, and only when asked:

* the security groups, interfaces, network ACLs, VPN routes and flow logs, and 90 days of inbound rule
  changes from CloudTrail, per region (``collectors.sg_flows``);
* the account's VPC flow logs in CloudWatch Logs, by Logs Insights, a slice of time at a time: hourly for the
  last day, six-hourly for the last week, daily beyond. Each slice is kept, so a later read only fills the gap.

The report (``build``) turns the slices into three timelines and the tables to act on:

* refused sources: addresses the rules (or a network ACL) turned away, which need a rule only if wanted;
* over-provisioned addresses: per logged security group, the addresses its rules allowed in at each time less
  every address ever seen anywhere in the account in the whole read (accepted or refused), summed over the
  groups, so a seen address is never counted and tightening any one group shows as a step down;
* active sources: who was let in, split into those also seen in the last 24 hours and those not (a DR test,
  failover or monthly batch shows as a burst of the second).

Every source is labelled: this or another scanned account (internal), a data centre (on-premises ranges,
VPN routes, other private space), AWS (with the service), a SaaS provider, or any other network by AS number.
"""

from __future__ import annotations

import contextvars
import gzip
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import ipintel
from .aws_session import caller_identity, make_session, member_session
from .cidr_collapse import DEFAULT_MAX_RULES, DEFAULT_PREFIX_THRESHOLD, DEFAULT_TOLERANCE, collapse_ips_to_cidrs
from .collectors import sg_flows
from .config import settings
from .issues import describe_exception
from .logging_config import get_logger

log = get_logger("sg_review")

SCHEMA = 1
HOUR, SIX, DAY = 3600, 6 * 3600, 86400
READ_DAYS = (1, 7, 30, 90, 180)
RANGES = {
    "24h": (DAY, HOUR),
    "1w": (7 * DAY, SIX),
    "1m": (30 * DAY, DAY),
    "3m": (90 * DAY, DAY),
    "6m": (180 * DAY, DAY),
}
LAG = 900  # flow logs reach CloudWatch up to ~10 minutes late: the newest quarter hour is left for the next read
WORKERS = 4
EVIDENCE_DAYS = 30  # fewer days of flow logs than this and no rule is called unused or ready to tighten
INSIGHTS_PER_GB = 0.005
TOP = 400  # sources listed per table (the charts count all of them)
CATS = ("internal", "datacentre", "aws", "saas", "internet")
CAT_NAME = {"internal": "Internal (scanned VPCs)", "datacentre": "Data centre and other private",
            "aws": "AWS", "saas": "External: SaaS", "internet": "External: other networks"}  # fmt: skip
PRIVATE = [ipintel.cidr_iv(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
ALL = [(0, 2**32 - 1)]
_ACCT_RE = re.compile(r"^[0-9]{12}$")


# ------------------------------------------------------------------------------------------- cache
def _dir():
    d = settings.data_dir / "sgreview"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _path(account: str):
    if not _ACCT_RE.fullmatch(account or ""):
        raise KeyError(account)
    return _dir() / f"{account}.json.gz"


def load(account: str) -> dict | None:
    try:
        with gzip.open(_path(account), "rt") as f:
            doc = json.load(f)
    except (OSError, ValueError, EOFError):
        return None
    return doc if doc.get("schema") == SCHEMA else None


def save(doc: dict) -> None:
    path = _path(doc["account"])
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "wb") as raw, gzip.open(raw, "wt") as f:
        json.dump(doc, f, separators=(",", ":"))
    os.replace(tmp, path)


def forget(account: str) -> bool:
    try:
        _path(account).unlink()
        return True
    except FileNotFoundError:
        return False


def new_doc(account: str, name: str, mode: str = "live") -> dict:
    return {"schema": SCHEMA, "account": account, "name": name, "mode": mode, "regions": {}, "chunks": [],
            "reads": []}  # fmt: skip


# ---------------------------------------------------------------------------------------- planning
def _floor(t: float, step: int) -> int:
    return int(t // step * step)


def read_end(now: float) -> int:
    return _floor(now - LAG, HOUR)


def plan(now: float, days: int, have=()) -> list[tuple[int, int]]:
    """The slices still to read for the last ``days``, newest first: hourly back to the six-hour boundary
    before a day ago, six-hourly back to the midnight before a week ago, then daily (all UTC). ``have`` is
    the (start, end) of slices already read; only what they leave uncovered is planned."""
    end = read_end(now)
    h0 = _floor(end - DAY, SIX)
    s0 = _floor(end - 7 * DAY, DAY)
    d0 = _floor(end - days * DAY, DAY)
    want = [(t, min(t + HOUR, end)) for t in range(h0, end, HOUR)]
    if days > 1:
        want += [(t, t + SIX) for t in range(s0, h0, SIX)]
    if days > 7:
        want += [(t, t + DAY) for t in range(d0, s0, DAY)]
    covered = ipintel.merge([(s, e - 1) for s, e in have if e > s])
    out = []
    for s, e in want:
        for a, b in ipintel.subtract([(s, e - 1)], covered):
            out.append((a, b + 1))
    return sorted(out, reverse=True)


def query_sets(snap: dict) -> list[dict]:
    """The flow logs one region's queries read: CloudWatch Logs destinations, active, in a format that has
    the fields needed, grouped by format (one query per format)."""
    by_fmt: dict[str, set] = {}
    for f in snap.get("flow_logs") or []:
        if (
            f["dest"] == "cloud-watch-logs"
            and f["group"]
            and f["status"] in ("ACTIVE", "")
            and sg_flows.readable(f["format"])
        ):
            by_fmt.setdefault(f["format"], set()).add(f["group"])  # fmt: skip
    return [{"format": k, "groups": sorted(v)} for k, v in sorted(by_fmt.items())]


def _vpc_ranges(snap: dict) -> list[str]:
    return sorted({c for v in snap.get("vpcs") or [] for c in v.get("cidrs") or [] if ":" not in c})


# ------------------------------------------------------------------------------------------- jobs
class Job:
    def __init__(self, account: str, name: str, days: int):
        self.account, self.name, self.days = account, name, days
        self.status = "running"
        self.done = self.total = 0
        self.bytes = 0
        self.message = "Starting"
        self.started = time.time()
        self.error: str | None = None
        self.cancelled = False

    def snapshot(self) -> dict:
        return {"account": self.account, "name": self.name, "days": self.days, "status": self.status,
                "done": self.done, "total": self.total, "message": self.message, "error": self.error,
                "bytes": self.bytes, "cost": round(self.bytes / 1e9 * INSIGHTS_PER_GB, 4),
                "elapsed": round(time.time() - self.started)}  # fmt: skip


_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()


def running() -> list[str]:
    with _jobs_lock:
        return [j.account for j in _jobs.values() if j.status == "running"]


def get_job(account: str) -> Job | None:
    with _jobs_lock:
        return _jobs.get(account)


def cancel(account: str) -> bool:
    job = get_job(account)
    if not job or job.status != "running":
        return False
    job.cancelled = True
    return True


def scan_account(scan: dict, account: str) -> dict | None:
    return next((a for a in scan.get("accounts") or [] if a.get("id") == account), None)


def account_facts(scan: dict, account: str) -> dict:
    return ((scan.get("assurance") or {}).get("accounts") or {}).get(account, {}).get("facts") or {}


def regions_of(scan: dict, account: str) -> list[str]:
    f = account_facts(scan, account)
    regs = set(f.get("access_network") or {}) | set(f.get("access_assets") or {})
    if not regs:
        regs = set((scan.get("params") or {}).get("regions") or [])
    return sorted(r for r in regs if isinstance(r, str) and r)


def start(scan: dict, account: str, days: int) -> Job:
    if days not in READ_DAYS:
        raise ValueError(f"read one of {', '.join(map(str, READ_DAYS))} days")
    acct = scan_account(scan, account)
    if not acct:
        raise ValueError(f"account {account} is not in this scan")
    cur = get_job(account)
    if cur and cur.status == "running":
        return cur
    job = Job(account, acct.get("name") or account, days)
    with _jobs_lock:
        _jobs[account] = job
    if scan.get("mode") == "demo":
        from .demo_sg import build_doc

        try:
            doc = build_doc(scan, account, time.time(), days, load(account))
            save(doc)
            job.bytes = doc["reads"][-1]["bytes"] if doc["reads"] else 0
            job.status, job.message, job.done, job.total = "done", "Read the demo account", 1, 1
        except Exception as exc:  # noqa: BLE001 - shown in the UI
            job.status, job.error = "failed", str(exc)
        return job
    threading.Thread(target=contextvars.copy_context().run, args=(_run, job, scan), daemon=True).start()
    return job


def _session(scan: dict, account: str, run_id: str):
    params = scan.get("params") or {}
    profile, role = params.get("profile"), params.get("role_name")
    base = make_session(profile)
    if caller_identity(base)["account_id"] == account:
        return base
    return member_session(base, profile, account, role, run_id)


def _run(job: Job, scan: dict) -> None:
    lock = threading.Lock()
    doc = load(job.account) or new_doc(job.account, job.name)
    try:
        sess = _session(scan, job.account, f"sgreview-{job.account}")
        now = time.time()
        tasks = []
        for region in regions_of(scan, job.account):
            if job.cancelled:
                break
            job.message = f"Reading security groups and flow logs in {region}"
            entry = doc["regions"].setdefault(region, {})
            try:
                entry["snapshot"] = sg_flows.snapshot(sess, region)
                entry["taken"] = now
                entry.pop("error", None)
            except Exception as exc:  # one region out of reach must not stop the others
                entry["error"] = describe_exception(exc)[1][:300]
                continue
            try:
                entry["history"] = sg_flows.rule_history(sess, region, sg_flows.utcnow())
            except Exception as exc:  # noqa: BLE001 - the report says history is unknown
                entry["history"] = {"events": [], "whole_since": now, "read": False,
                                    "error": describe_exception(exc)[1][:300]}  # fmt: skip
            qsets = query_sets(entry["snapshot"])
            entry["query_sets"] = qsets
            if not qsets:
                continue
            have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == region and c["st"] in ("ok", "cut")]
            vpcs = _vpc_ranges(entry["snapshot"])
            tasks += [(region, s, e, qsets, vpcs) for s, e in plan(now, job.days, have)]
        job.total = len(tasks)
        logs_clients: dict = {}

        def one(task):
            region, s, e, qsets, vpcs = task
            if job.cancelled:
                return
            with lock:
                logs = logs_clients.get(region) or logs_clients.setdefault(
                    region, sess.client("logs", region_name=region, config=sg_flows.BOTO_CONFIG)
                )
            job.message = f"Reading flow logs in {region}: {_stamp(s)}"
            for chunk in read_chunk(logs, region, s, e, qsets, vpcs, lambda: job.cancelled):
                with lock:
                    doc["chunks"].append(chunk)
                    job.bytes += chunk["b"]
            job.done += 1
            if job.done % 12 == 0:
                with lock:
                    save(doc)

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            list(pool.map(lambda t: contextvars.copy_context().run(one, t), tasks))
        doc["reads"].append({"at": now, "days": job.days, "bytes": job.bytes, "slices": job.done})
        job.status = "cancelled" if job.cancelled else "done"
        job.message = "Stopped" if job.cancelled else "Done"
    except Exception as exc:  # noqa: BLE001 - shown in the UI
        log.warning("security group read for %s failed: %s", job.account, exc)
        job.status, job.error = "failed", describe_exception(exc)[1][:400]
    finally:
        with lock:
            save(doc)


def _stamp(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%d %b %H:%M")


def read_chunk(logs, region: str, s: int, e: int, qsets: list, vpcs: list, cancelled=lambda: False) -> list[dict]:
    """One slice read (split in halves, down to an hour, while the detail query hits the row limit)."""
    rows, pub, nbytes, cut, pub_cut, errors = [], [], 0, False, False, []
    for q in qsets:
        rs, b, status = None, 0, ""
        for fold in (True, False):
            query = sg_flows.detail_query(q["format"], vpcs, fold=fold)
            rs, b, status = sg_flows.run_query(logs, q["groups"], query, s, e, cancelled=cancelled)
            nbytes += b
            if rs is not None or status in ("Cancelled", "Timeout"):
                break
        if rs is None:
            errors.append(f"detail query {status}")
            continue
        if len(rs) >= sg_flows.ROWS:
            if e - s > HOUR:
                mid = s + _floor((e - s) // 2, HOUR) if e - s >= 2 * HOUR else (s + e) // 2
                parts = [
                    *read_chunk(logs, region, mid, e, qsets, vpcs, cancelled),
                    *read_chunk(logs, region, s, mid, qsets, vpcs, cancelled),
                ]
                parts[0]["b"] += nbytes  # the full slice's query was billed too
                return parts  # fmt: skip
            cut = True
        rows += [[r.get("src"), r.get("dst"), r.get("eni"), r.get("proto"), _int(r.get("dport")), r.get("action"),
                  _int(r.get("flows"))] for r in rs]  # fmt: skip
        ps, b, status = sg_flows.run_query(logs, q["groups"], sg_flows.public_query(q["format"], vpcs), s, e,
                                           cancelled=cancelled)  # fmt: skip
        nbytes += b
        if ps is None:
            errors.append(f"refused-internet query {status}")
            continue
        pub_cut = pub_cut or len(ps) >= sg_flows.ROWS
        pub += [[r.get("src"), _int(r.get("flows")), _int(r.get("ports")), _int(r.get("dsts")), r.get("dst"),
                 r.get("eni"), _int(r.get("port")), r.get("proto")] for r in ps]  # fmt: skip
    st = "failed" if errors and not rows and not pub else ("cut" if cut else "ok")
    return [{"r": region, "s": s, "e": e, "st": st, "b": nbytes, "rows": rows, "pub": pub, "pc": pub_cut,
             "err": "; ".join(errors)}]  # fmt: skip


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def estimate(doc: dict | None, scan: dict, account: str, now: float | None = None) -> dict:
    """What each read range would cost, from the bytes per second of log earlier reads scanned."""
    now = now or time.time()
    doc = doc or new_doc(account, "")
    secs = sum(c["e"] - c["s"] for c in doc["chunks"] if c["st"] in ("ok", "cut"))
    nbytes = sum(c["b"] for c in doc["chunks"])
    rate = nbytes / secs if secs else None
    out = []
    regions = [r for r, x in doc["regions"].items() if x.get("query_sets")] or regions_of(scan, account)
    for days in READ_DAYS:
        missing = 0
        for r in regions:
            have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == r and c["st"] in ("ok", "cut")]
            missing += sum(e - s for s, e in plan(now, days, have))
        est = rate * missing if rate is not None else None
        out.append({"days": days, "missing_hours": round(missing / HOUR, 1), "bytes": est,
                    "cost": round(est / 1e9 * INSIGHTS_PER_GB, 2) if est is not None else None})  # fmt: skip
    return {"rate": rate, "ranges": out, "spent_bytes": nbytes, "spent": round(nbytes / 1e9 * INSIGHTS_PER_GB, 2)}


# ---------------------------------------------------------------------------------------- labelling
def _iv(cidrs) -> list[tuple[int, int]]:
    return ipintel.merge([x for x in map(ipintel.cidr_iv, cidrs) if x])


class Labeller:
    """Category and name of a source address; one lookup per address."""

    def __init__(self, doc: dict, scan: dict | None, onprem: str = ""):
        from .account_map import parse_ranges
        from .network_review import _cidrs

        self.intel = ipintel.get()
        self.nets: list[tuple[int, int, str, str]] = []  # (first, last, category, name), most specific first
        own = []
        for snap in (x.get("snapshot") or {} for x in doc["regions"].values()):
            for v in snap.get("vpcs") or []:
                for c in v.get("cidrs") or []:
                    iv = ipintel.cidr_iv(c)
                    if iv and ":" not in c:
                        own.append(iv)
                        self.nets.append((*iv, "internal", f"This account, {v.get('name') or v['id']}"))
        others = []
        for a in (scan or {}).get("accounts") or []:
            if a.get("id") == doc["account"]:
                continue
            for n in _cidrs(account_facts(scan, a["id"])):
                if n.version == 4:
                    iv = (int(n.network_address), int(n.broadcast_address))
                    others.append(iv)
                    self.nets.append((*iv, "internal", f"{a.get('name') or a['id']} ({a['id']})"))
        dc = []
        for net, name in parse_ranges(onprem):
            if net.version == 4:
                iv = (int(net.network_address), int(net.broadcast_address))
                dc.append(iv)
                self.nets.append((*iv, "datacentre", name))
        for snap in (x.get("snapshot") or {} for x in doc["regions"].values()):
            for v in snap.get("vpns") or []:
                for c in v.get("routes") or []:
                    iv = ipintel.cidr_iv(c)
                    if iv:
                        dc.append(iv)
                        self.nets.append((*iv, "datacentre", f"Behind VPN {v['name']}"))
        self.nets.sort(key=lambda n: n[1] - n[0])
        internal = ipintel.merge(own + others)
        private = ipintel.subtract(ipintel.merge(PRIVATE + dc), internal)
        aws = ipintel.subtract(self.intel.aws_intervals(), ipintel.merge(internal + private))
        saas = ipintel.subtract(self.intel.saas.intervals(), ipintel.merge(internal + private + aws))
        rest = ipintel.subtract(ALL, ipintel.merge(internal + private + aws + saas))
        self.cat_iv = {"internal": internal, "datacentre": private, "aws": aws, "saas": saas, "internet": rest}
        self._memo: dict[str, dict] = {}

    def __call__(self, ip: str) -> dict:
        hit = self._memo.get(ip)
        if hit:
            return hit
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return {"cat": "internet", "name": str(ip)}
        out = None
        for first, last, cat, name in self.nets:
            if first <= n <= last:
                out = {"cat": cat, "name": name}
                break
        if out is None and any(a <= n <= b for a, b in PRIVATE):
            out = {"cat": "datacentre", "name": "Private address outside every scanned VPC"}
        if out is None:
            lab = self.intel.label(ip)
            out = {"cat": lab["kind"], "name": lab["name"]}
            if lab.get("asn"):
                out["asn"] = f"AS{lab['asn']} {lab.get('owner', '')}".strip() + (
                    f" ({lab['country']})" if lab.get("country") else ""
                )
        self._memo[ip] = out
        return out


# ------------------------------------------------------------------------------------------- rules
def _ip(s) -> int | None:
    try:
        return int(ipaddress.IPv4Address(s))
    except (ValueError, TypeError):
        return None


def port_matches(rule: dict, proto: str, port: int) -> bool:
    rp = str(rule["proto"])
    if rp == "-1":
        return True
    if rp != str(proto):
        return False
    if rp not in ("6", "17"):
        return True
    if port >= sg_flows.EPHEMERAL:  # folded: any port from here up
        return rule["to"] >= sg_flows.EPHEMERAL
    return rule["from"] <= port <= rule["to"]


def ports_label(rule: dict) -> str:
    p = {"6": "tcp", "17": "udp", "1": "icmp", "-1": "all"}.get(str(rule["proto"]), f"proto {rule['proto']}")
    if p in ("all", "icmp") or (rule["from"], rule["to"]) == (0, 65535):
        return p if p != "all" else "all traffic"
    return f"{p} {rule['from']}" if rule["from"] == rule["to"] else f"{p} {rule['from']}-{rule['to']}"


def _entries(rule: dict) -> list[str]:
    return list(rule.get("cidrs") or []) + list(rule.get("pls") or [])


def nacl_verdict(nacl: dict | None, src: int, proto: str, port: int) -> dict | None:
    """The first inbound network ACL entry matching, when it denies; None when the ACL allows."""
    for x in (nacl or {}).get("entries") or []:
        iv = ipintel.cidr_iv(x["cidr"])
        if not iv or not iv[0] <= src <= iv[1]:
            continue
        if x["proto"] not in ("-1", str(proto)):
            continue
        if x["proto"] in ("6", "17") and not (x["from"] <= port <= x["to"]):
            continue
        return None if x["allow"] else {"acl": nacl["id"], "rule": x["n"]}
    return None


# ------------------------------------------------------------------------------------------- report
def _coverage(snap: dict) -> dict:
    """Interface id -> (covered for accepted traffic, covered for refused, earliest such flow log)."""
    out = {}
    logs = [f for f in snap.get("flow_logs") or [] if f["dest"] == "cloud-watch-logs" and f["status"] in ("ACTIVE", "")
            and sg_flows.readable(f["format"])]  # fmt: skip
    for eid, e in (snap.get("enis") or {}).items():
        mine = [f for f in logs if f["resource"] in (eid, e.get("subnet"), e.get("vpc"))]
        acc = [f for f in mine if f["traffic"] in ("ALL", "ACCEPT")]
        rej = [f for f in mine if f["traffic"] in ("ALL", "REJECT")]
        created = min((f["created"] for f in acc if f.get("created")), default=None)
        out[eid] = (bool(acc), bool(rej), created)
    return out


def _state_at(now_entries: set, events: list, t: float) -> tuple[set, bool]:
    """A group's inbound entries at time t, worked back from today's through the changes after t."""
    state, known = set(now_entries), True
    for ev in reversed(events):
        if ev["t"] <= t:
            break
        if ev["unknown"]:
            known = False
            break
        state -= {tuple(x) for x in ev["added"]}
        state |= {tuple(x) for x in ev["removed"]}
    return state, known


def build(doc: dict, scan: dict | None = None, range_key: str = "1m", onprem: str = "") -> dict:
    span, step = RANGES.get(range_key, RANGES["1m"])
    chunks = [c for c in doc["chunks"] if c["st"] in ("ok", "cut")]
    lab = Labeller(doc, scan, onprem)
    end = max((c["e"] for c in chunks), default=read_end(time.time()))
    start = _floor(end - span, step)
    nbins = max(1, -(-(end - start) // step))
    bins = [start + i * step for i in range(nbins)]
    today = end - DAY

    enis, groups, snaps = {}, {}, {}
    for region, x in doc["regions"].items():
        snap = x.get("snapshot") or {}
        snaps[region] = snap
        cov = _coverage(snap)
        for eid, e in (snap.get("enis") or {}).items():
            enis[eid] = {**e, "region": region, "cov": cov.get(eid, (False, False, None))}
        for gid, g in (snap.get("groups") or {}).items():
            groups[gid] = {**g, "id": gid, "region": region, "enis": []}
    for eid, e in enis.items():
        for gid in e["groups"]:
            if gid in groups:
                groups[gid]["enis"].append(eid)
    own_ips = {ip for e in enis.values() for ip in e["ips"]}

    def relevant(eni_id, src, dst) -> bool:
        if src in own_ips and (eni_id not in enis or src in enis[eni_id]["ips"]):
            return False  # the interface's own outbound record
        e = enis.get(eni_id)
        if e is None:
            return True  # a deleted interface: kept, as unattributed
        if not e["groups"]:
            return False  # NAT gateways, transit gateway attachments: no security group decides
        return dst in e["ips"] or any(ipintel.cidr_iv(p) and _in(dst, p) for p in e.get("prefixes") or [])

    seen: set[str] = set()
    rej: dict[str, dict] = {}
    act: dict[str, dict] = {}
    accepted_rows = []  # (src, dst, eni, proto, dport, flows, chunk)
    region_first: dict[str, int] = {}
    cut_regions, pub_cut = set(), 0
    for c in chunks:
        region_first[c["r"]] = min(region_first.get(c["r"], c["s"]), c["s"])
        if c["st"] == "cut":
            cut_regions.add(c["r"])
        pub_cut += bool(c.get("pc"))
        b = (c["s"] - start) // step if c["s"] >= start else None
        in_view = b is not None and 0 <= b < nbins
        for src, dst, eni, proto, dport, action, flows in c["rows"]:
            if not src:
                continue
            seen.add(src)
            if not relevant(eni, src, dst):
                continue
            if action == "ACCEPT":
                accepted_rows.append((src, dst, eni, str(proto), dport, flows, c))
                if dport >= sg_flows.EPHEMERAL and not _rule_covers(groups, enis.get(eni), proto, dport):
                    continue  # replies to the account's own connections
                a = act.setdefault(src, {"bins": set(), "flows": 0, "first": c["s"], "last": c["e"], "days": set(),
                                         "targets": {}, "today": False})  # fmt: skip
                a["days"].add(c["s"] // DAY)
                a["first"], a["last"] = min(a["first"], c["s"]), max(a["last"], c["e"])
                a["today"] = a["today"] or c["s"] >= today
                if in_view:
                    a["bins"].add(b)
                    a["flows"] += flows
                    k = (eni, str(proto), dport)
                    a["targets"][k] = a["targets"].get(k, 0) + flows
            elif in_view and dport < sg_flows.EPHEMERAL:
                _refused(rej, src, b, c, flows, (eni, str(proto), dport, dst))
        for src, flows, ports, dsts, dst, eni, port, proto in c.get("pub") or []:
            if not src:
                continue
            seen.add(src)
            if in_view and (port < sg_flows.EPHEMERAL or ports > 1):
                r = _refused(rej, src, b, c, flows, (eni, str(proto), port, dst))
                r["ports"] = max(r.get("ports", 1), ports)
                r["dsts"] = max(r.get("dsts", 1), dsts)

    seen_iv = ipintel.merge([(n, n) for n in map(_ip, seen) if n is not None])

    # ---- the three series
    def zeros():
        return {k: [0] * nbins for k in CATS}

    rej_series = zeros()
    act_today, act_older = zeros(), zeros()
    for src, r in rej.items():
        cat = lab(src)["cat"]
        for b in r["bins"]:
            rej_series[cat][b] += 1
    for src, a in act.items():
        cat = lab(src)["cat"]
        for b in a["bins"]:
            (act_today if a["today"] else act_older)[cat][b] += 1

    # ---- rules: today's, worked back through the changes for the over-provisioned line
    hist = {r: (x.get("history") or {}) for r, x in doc["regions"].items()}
    ev_by_group: dict[str, list] = {}
    for h in hist.values():
        for ev in h.get("events") or []:
            ev_by_group.setdefault(ev["group"], []).append(ev)
    for evs in ev_by_group.values():
        evs.sort(key=lambda e: e["t"])

    def logged(g) -> bool:
        return bool(g["enis"]) and g["region"] in region_first and all(enis[e]["cov"][0] for e in g["enis"])

    def expand(entry: str, region: str) -> list[tuple[int, int]]:
        if entry.startswith("pl-"):
            return _iv((snaps.get(region, {}).get("prefix_lists") or {}).get(entry, []))
        return _iv([entry])

    over_series = zeros()
    frozen_groups = set()
    logged_groups = [g for g in groups.values() if logged(g)]
    now_entries = {
        g["id"]: {(r["proto"], r["from"], r["to"], s) for r in g["rules"] for s in _entries(r)} for g in logged_groups
    }
    memo: dict[tuple, list] = {}
    for i, t0 in enumerate(bins):
        t = min(t0 + step, end)
        total = [0] * len(CATS)
        for g in logged_groups:
            state, known = _state_at(now_entries[g["id"]], ev_by_group.get(g["id"], []), t)
            if not known:
                frozen_groups.add(g["id"])
            key = (g["region"], frozenset(x[3] for x in state if x[3] != "0.0.0.0/0"))
            if key not in memo:
                iv = ipintel.merge([v for src in key[1] for v in expand(src, key[0])])
                over = ipintel.subtract(iv, seen_iv)
                memo[key] = [ipintel.size(ipintel.intersect(over, lab.cat_iv[k])) for k in CATS]
            total = [a + b for a, b in zip(total, memo[key], strict=True)]
        for k, n in zip(CATS, total, strict=True):
            over_series[k][i] = n
    markers = [
        {"t": ev["t"], "bin": int((ev["t"] - start) // step), "group": ev["group"],
         "name": groups.get(ev["group"], {}).get("name", ev["group"]), "event": ev["name"], "who": ev["who"],
         "added": [x[3] for x in ev["added"]], "removed": [x[3] for x in ev["removed"]], "unknown": ev["unknown"]}
        for evs in ev_by_group.values() for ev in evs if start <= ev["t"] < end
    ]  # fmt: skip

    rules = _rules_table(doc, groups, enis, accepted_rows, seen, seen_iv, lab, region_first, cut_regions, end)
    open_rules = [r for r in rules if r["status"] == "open"]

    # ---- tables
    def src_row(src, x):
        lb = lab(src)
        return {"src": src, **lb, "flows": x["flows"], "bins": sorted(x["bins"]), "first": x["first"],
                "last": x["last"]}  # fmt: skip

    refused = []
    for src, r in sorted(rej.items(), key=lambda kv: -kv[1]["flows"])[:TOP]:
        row = src_row(src, r)
        targets = []
        for (eni, proto, port, dst), flows in sorted(r["targets"].items(), key=lambda kv: -kv[1])[:5]:
            e = enis.get(eni) or {}
            targets.append({"eni": eni, "dst": dst, "proto": proto, "port": port, "flows": flows,
                            "kind": e.get("kind", "deleted interface"), "groups": e.get("groups", []),
                            "by": _refused_by(src, e, groups, snaps, proto, port)})  # fmt: skip
        row.update(targets=targets, ports=r.get("ports", len({t[2] for t in r["targets"]})), dsts=r.get("dsts", 1))
        row["sweep"] = row["ports"] >= 10 or row["dsts"] >= 5
        refused.append(row)
    suggestions = _suggest(rej, enis, groups, snaps, lab)

    active = []
    for src, a in sorted(act.items(), key=lambda kv: -kv[1]["flows"])[:TOP]:
        if not a["bins"]:
            continue
        row = src_row(src, a)
        row.update(today=a["today"], days=len(a["days"]),
                   targets=[{"eni": k[0], "proto": k[1], "port": k[2], "flows": v,
                             "groups": (enis.get(k[0]) or {}).get("groups", [])}
                            for k, v in sorted(a["targets"].items(), key=lambda kv: -kv[1])[:5]])  # fmt: skip
        active.append(row)

    regions = {}
    for region, x in doc["regions"].items():
        snap = x.get("snapshot") or {}
        regions[region] = {
            "error": x.get("error"),
            "taken": x.get("taken"),
            "query_sets": x.get("query_sets") or [],
            "flow_logs": len(snap.get("flow_logs") or []),
            "unreadable": [f["id"] for f in snap.get("flow_logs") or []
                           if f["dest"] != "cloud-watch-logs" or not sg_flows.readable(f["format"])],
            "history": {"read": (x.get("history") or {}).get("read", False),
                        "since": (x.get("history") or {}).get("whole_since"),
                        "error": (x.get("history") or {}).get("error")},
            "first": region_first.get(region),
            "cut": region in cut_regions,
            "groups": sum(1 for g in groups.values() if g["region"] == region),
        }  # fmt: skip
    not_logged = [g for g in groups.values() if g["enis"] and not logged(g)]
    last = len(bins) - 1
    return {
        "account": doc["account"],
        "name": doc.get("name", ""),
        "mode": doc.get("mode", "live"),
        "range": range_key if range_key in RANGES else "1m",
        "step": step,
        "bins": bins,
        "end": end,
        "categories": [{"key": k, "name": CAT_NAME[k]} for k in CATS],
        "series": {"refused": rej_series, "over": over_series, "active_today": act_today, "active_older": act_older},
        "markers": markers,
        "summary": {
            "refused": len(rej),
            "refused_internal": sum(1 for s in rej if lab(s)["cat"] in ("internal", "datacentre")),
            "active": sum(1 for a in act.values() if a["bins"]),
            "active_older": sum(1 for a in act.values() if a["bins"] and not a["today"]),
            "over_now": sum(over_series[k][last] for k in CATS),
            "over_by_cat": {k: over_series[k][last] for k in CATS},
            "tighten": sum(1 for r in rules if r["status"] == "tighten"),
            "unused": sum(1 for r in rules if r["status"] == "unused"),
            "watch": sum(1 for r in rules if r["status"] == "watch"),
            "open": len(open_rules),
            "not_logged": len(not_logged),
            "not_logged_groups": [{"id": g["id"], "name": g["name"], "region": g["region"]} for g in not_logged][:50],
            "frozen": sorted(frozen_groups),
            "seen": len(seen),
            "evidence_since": min(region_first.values(), default=None),
            "cut": sorted(cut_regions),
            "public_cut": pub_cut,
            "slices": len(chunks),
            "failed": sum(1 for c in doc["chunks"] if c["st"] == "failed"),
            "intel_seed": ipintel.get().counts.get("seed", []),
        },
        "regions": regions,
        "rules": rules,
        "refused": refused,
        "suggestions": suggestions,
        "active": active,
    }


def _in(ip: str, cidr: str) -> bool:
    n, iv = _ip(ip), ipintel.cidr_iv(cidr)
    return n is not None and iv is not None and iv[0] <= n <= iv[1]


def _rule_covers(groups: dict, eni: dict | None, proto, port: int) -> bool:
    if not eni:
        return False
    return any(port_matches(r, str(proto), port) and _entries(r) for g in eni["groups"]
               for r in (groups.get(g) or {}).get("rules") or [])  # fmt: skip


def _refused(rej: dict, src: str, b: int, c: dict, flows: int, target: tuple) -> dict:
    r = rej.setdefault(src, {"bins": set(), "flows": 0, "first": c["s"], "last": c["e"], "targets": {}})
    r["bins"].add(b)
    r["flows"] += flows
    r["first"], r["last"] = min(r["first"], c["s"]), max(r["last"], c["e"])
    r["targets"][target] = r["targets"].get(target, 0) + flows
    return r


def _allows_now(groups: dict, e: dict, src: str, proto: str, port: int) -> list[str]:
    n = _ip(src)
    out = []
    for gid in e.get("groups") or []:
        for r in (groups.get(gid) or {}).get("rules") or []:
            if not port_matches(r, proto, port):
                continue
            ivs = _iv(r.get("cidrs") or [])
            if n is not None and any(a <= n <= b for a, b in ivs):
                out.append(gid)
    return out


def _refused_by(src: str, e: dict, groups: dict, snaps: dict, proto: str, port: int) -> str:
    if not e:
        return "Interface since deleted"
    n = _ip(src)
    nacl = (snaps.get(e["region"], {}).get("nacls") or {}).get(e.get("subnet", ""))
    if n is not None and nacl_verdict(nacl, n, proto, port):
        v = nacl_verdict(nacl, n, proto, port)
        return f"Network ACL {v['acl']} rule {v['rule']}"
    if _allows_now(groups, e, src, proto, port):
        return "Security group (a rule added since allows it)"
    return "Security group"


def _suggest(rej: dict, enis: dict, groups: dict, snaps: dict, lab) -> list[dict]:
    """Rules that would let in the refused private sources, per group, protocol and port: only to add if
    the traffic is wanted."""
    want: dict[tuple, dict] = {}
    for src, r in rej.items():
        lb = lab(src)
        if lb["cat"] not in ("internal", "datacentre"):
            continue
        for (eni, proto, port, _dst), flows in r["targets"].items():
            e = enis.get(eni)
            if not e or not e["groups"] or _refused_by(src, e, groups, snaps, proto, port) != "Security group":
                continue
            k = (e["groups"][0], proto, port)
            w = want.setdefault(k, {"srcs": set(), "flows": 0, "names": set()})
            w["srcs"].add(src)
            w["flows"] += flows
            w["names"].add(lb["name"])
    out = []
    for (gid, proto, port), w in sorted(want.items(), key=lambda kv: -kv[1]["flows"])[:100]:
        g = groups.get(gid) or {}
        out.append({"group": gid, "name": g.get("name", ""), "region": g.get("region", ""),
                    "ports": ports_label({"proto": proto, "from": port, "to": port}), "sources": len(w["srcs"]),
                    "flows": w["flows"], "from": sorted(w["names"])[:5],
                    "cidrs": collapse_ips_to_cidrs(sorted(w["srcs"]), DEFAULT_MAX_RULES, 0.0)})  # fmt: skip
    return out


def _rules_table(doc, groups, enis, accepted_rows, seen, seen_iv, lab, region_first, cut_regions, end) -> list[dict]:
    by_eni: dict[str, list] = {}
    deleted: list = []
    for row in accepted_rows:
        if row[2] in enis:
            by_eni.setdefault(row[2], []).append(row)
        else:
            deleted.append(row)
    seen_ints = sorted(n for n in map(_ip, seen) if n is not None)
    out = []
    for g in groups.values():
        if not g["enis"]:
            continue
        snap = (doc["regions"].get(g["region"]) or {}).get("snapshot") or {}
        vpc_iv = _iv(next((v["cidrs"] for v in snap.get("vpcs") or [] if v["id"] == g["vpc"]), []))
        logged = g["region"] in region_first and all(enis[e]["cov"][0] for e in g["enis"])
        created = [enis[e]["cov"][2] for e in g["enis"] if enis[e]["cov"][2]]
        since = max([region_first.get(g["region"], end)] + created)
        days = max(0, (end - since) / DAY)
        rows = [r for e in g["enis"] for r in by_eni.get(e, [])]
        for rule in g["rules"]:
            for entry in _entries(rule):
                ivs = (_iv((snap.get("prefix_lists") or {}).get(entry, [])) if entry.startswith("pl-")
                       else _iv([entry]))  # fmt: skip
                if not ivs:
                    continue
                allowed = ipintel.size(ivs)

                def inside(ip, ivs=ivs):
                    n = _ip(ip)
                    return n is not None and any(a <= n <= b for a, b in ivs)

                here: dict[str, list] = {}
                for src, _dst, _eni, proto, dport, flows, c in rows:
                    if port_matches(rule, proto, dport) and inside(src):
                        h = here.setdefault(src, [0, 0])
                        h[0] += flows
                        h[1] = max(h[1], c["e"])
                unattr = {src for src, dst, _e, proto, dport, _f, _c in deleted
                          if port_matches(rule, proto, dport) and inside(src)
                          and (n := _ip(dst)) is not None and any(a <= n <= b for a, b in vpc_iv)}  # fmt: skip
                n_seen = sum(bisect_right(seen_ints, b) - bisect_right(seen_ints, a - 1) for a, b in ivs)
                never = ipintel.size(ipintel.subtract(ivs, seen_iv))
                row = {"region": g["region"], "group": g["id"], "gname": g["name"], "vpc": g["vpc"],
                       "enis": len(g["enis"]), "ports": ports_label(rule), "proto": rule["proto"],
                       "from": rule["from"], "to": rule["to"], "source": entry,
                       "desc": (rule.get("descs") or {}).get(entry, ""), "allowed": allowed, "here": len(here),
                       "elsewhere": max(0, n_seen - len(here) - len(unattr - set(here))),
                       "unattributed": len(unattr - set(here)), "never": never,
                       "last_used": max((h[1] for h in here.values()), default=None), "since": since,
                       "days": round(days, 1), "suggest": [], "suggest_size": None, "note": ""}  # fmt: skip
                row["top"] = [{"src": s, **lab(s), "flows": h[0]}
                              for s, h in sorted(here.items(), key=lambda kv: -kv[1][0])[:8]]  # fmt: skip
                row["status"], row["note"] = _status(row, rule, entry, logged, g, cut_regions, days)
                if row["status"] == "tighten":
                    keep = sorted(set(here) | unattr)
                    within = ipaddress.IPv4Network(entry, strict=False) if not entry.startswith("pl-") else None
                    cidrs = collapse_ips_to_cidrs(keep, DEFAULT_MAX_RULES, DEFAULT_TOLERANCE)
                    if within is not None:
                        cidrs = [c if ipaddress.IPv4Network(c).subnet_of(within) else str(within) for c in cidrs]
                        cidrs = [str(n) for n in ipaddress.collapse_addresses(map(ipaddress.IPv4Network, cidrs))]
                    row["suggest"] = cidrs
                    row["suggest_size"] = ipintel.size(_iv(cidrs))
                    if row["suggest_size"] >= allowed:
                        row["status"], row["note"] = "used", "In use across the range: nothing to take away"
                        row["suggest"], row["suggest_size"] = [], None
                out.append(row)
    rank = {"tighten": 0, "unused": 1, "open": 2, "watch": 3, "incomplete": 4, "not logged": 5, "used": 6}
    out.sort(key=lambda r: (rank.get(r["status"], 9), -r["never"]))
    return out


def _status(row, rule, entry, logged, g, cut_regions, days) -> tuple[str, str]:
    if entry == "0.0.0.0/0":
        return "open", "Open to every address: the users are listed; a prefix list or narrower range may do"
    if not logged:
        return "not logged", "Some of this group's interfaces have no flow log (accepted traffic) in CloudWatch Logs"
    if g["region"] in cut_regions:
        return "incomplete", "Some slices hit the 10,000 row limit even at an hour: not safe to act on"
    if days < EVIDENCE_DAYS:
        return "watch", f"Only {days:.0f} days of flow logs: read a longer range before changing this rule"
    if not row["here"] and not row["unattributed"]:
        return "unused", f"No connection matched this rule in {days:.0f} days"
    private = not entry.startswith("pl-") and any(
        ipintel.cidr_iv(entry) and a <= ipintel.cidr_iv(entry)[0] and ipintel.cidr_iv(entry)[1] <= b
        for a, b in PRIVATE[:3]
    )
    plen = int(entry.split("/")[1]) if "/" in entry else 32
    if private and plen < DEFAULT_PREFIX_THRESHOLD and row["never"]:
        return "tighten", "Wider than needed: the suggested ranges keep every address seen, with 30% headroom"
    if not private and not entry.startswith("pl-") and plen < 32 and row["never"]:
        return "tighten", "Public range: the suggestion keeps only the addresses seen; check with the partner first"
    return "used", ""


def approved(doc: dict, region: str) -> dict:
    """sg-tightener's approved list (v2) for one region, from the accepted connections read."""
    snap = (doc["regions"].get(region) or {}).get("snapshot") or {}
    enis = snap.get("enis") or {}
    own = {ip for e in enis.values() for ip in e["ips"]}
    flows, warnings = set(), []
    folded = 0
    for c in doc["chunks"]:
        if c["r"] != region or c["st"] not in ("ok", "cut"):
            continue
        for src, dst, eni, proto, dport, action, _f in c["rows"]:
            if action != "ACCEPT" or not src or src in own:
                continue
            e = enis.get(eni)
            if e is not None and dst not in e["ips"]:
                continue
            if dport >= sg_flows.EPHEMERAL:
                folded += 1
                continue
            flows.add((src, dst, dport, int(proto) if str(proto).isdigit() else proto, eni))
    if folded:
        warnings.append(f"{folded} records to ports {sg_flows.EPHEMERAL} and up were read folded together and left out")
    qsets = (doc["regions"].get(region) or {}).get("query_sets") or []
    first = min((c["s"] for c in doc["chunks"] if c["r"] == region), default=None)
    return {
        "schema": "sg-tightener.approved/v2",
        "region": region,
        "days": round((time.time() - first) / DAY) if first else 0,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "aws-risk-review",
        "flow_log_check": {"verified": True, "fields": sg_flows.fields_of(qsets[0]["format"]) if qsets else [],
                           "warnings": warnings,
                           "resources": sorted({f["resource"] for f in snap.get("flow_logs") or []})},  # fmt: skip
        "ips": sorted({f[0] for f in flows}, key=lambda s: _ip(s) or 0),
        "flows": [{"src": a, "dst": b, "dstport": p, "protocol": pr, "interface": i}
                  for a, b, p, pr, i in sorted(flows, key=str)],
    }  # fmt: skip
