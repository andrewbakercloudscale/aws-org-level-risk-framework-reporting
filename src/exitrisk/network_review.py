"""Network Traffic Review: failed network traffic in every account of a Cloud Assurance scan.

Read from the facts the Access Graph reads (collectors/access.py), estate wide instead of one account:

* VPC flow logs (when the scan read them): connections refused by security groups and network ACLs, TCP
  connections nobody answered (the SYN sent again and again: a timeout) and connections reset before any data,
  each with its bytes, and whether the source and target failed in the days before (new today);
* CloudWatch metrics (always read with Cloud Assurance): load balancer resets, TLS and target errors, NAT
  gateway connections with no response and port exhaustion, transit gateway drops, firewall and WAF blocks,
  endpoint drops, database sign-in failures;
* CloudTrail (when read): API calls refused and failed console sign-ins.

Each failed conversation is placed by its far end: the internet, another scanned account, or a private network
outside every scanned VPC (on premises, or an account not scanned). Recon is a source refused on many ports or
addresses, or in several accounts (recon.py), and an address inside the estate refused on many ports.

Flow logs record only accepted or rejected, and the SYN, SYN-ACK, FIN and RST flags: zero windows,
retransmissions and other TCP detail need a packet capture, and are named as not measured.
"""

from __future__ import annotations

import ipaddress
import re
import time

from . import riskpoints
from .account_map import FAIL_METRIC_CAT, parse_ranges
from .filtering import AccountFilter
from .logging_config import get_logger
from .recon import ENUM, LOGINS, SWEEP
from .resilience import owner_of

log = get_logger("network_review")

INSIGHTS_PER_GB = 0.005  # US$ per GB Logs Insights scans (us-east-1; some regions cost more)
INTERNAL_SWEEP = 10  # an address inside the estate refused on this many ports: a scan from inside
TOP = 10  # failed conversations kept per account
NEW_ROWS = 200
SOURCES = 100
PORTS = {"22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP", "443": "HTTPS", "445": "SMB",
         "3389": "RDP", "5432": "PostgreSQL", "3306": "MySQL", "1433": "SQL Server", "1521": "Oracle",
         "27017": "MongoDB", "6379": "Redis", "9200": "OpenSearch", "11211": "Memcached", "5439": "Redshift",
         "2049": "NFS", "8080": "HTTP alt", "8443": "HTTPS alt", "9092": "Kafka", "5672": "AMQP",
         "6443": "Kubernetes API", "2379": "etcd", "10250": "kubelet"}  # fmt: skip

# Each kind of failure: key, group, what, kind, unit (what the count counts). Kinds: "security" (worth a look
# as a possible attack or
# misuse), "health" (something that should have worked did not), "defence" (a control turning traffic away,
# as it should: counted, not a fault), "info" (shown, judged by neither).
CLASSES = [
    ("refused_in_internet", "Flow logs", "Refused coming in from the internet", "defence", "connections"),
    (
        "refused_in_private",
        "Flow logs",
        "Refused coming in from other accounts or private networks",
        "security",
        "connections",
    ),
    ("refused_internal", "Flow logs", "Refused inside the account", "health", "connections"),
    ("refused_out", "Flow logs", "Refused going out", "health", "connections"),
    (
        "unanswered",
        "Flow logs",
        "Not answered: connection attempts retried with no reply (timeouts)",
        "health",
        "connections",
    ),
    ("reset", "Flow logs", "Reset before any data (RST): no one listening, or cut", "info", "connections"),
    ("trail_denied", "API calls (CloudTrail)", "Calls refused by IAM or a policy", "security", "API calls"),
    ("trail_login", "API calls (CloudTrail)", "Failed console sign-ins", "security", "sign-ins"),
    ("waf_blocked", "WAF", "Requests blocked by web ACL rules", "defence", "requests"),
    ("nfw_dropped", "Network Firewall", "Packets dropped by firewall rules", "defence", "packets"),
    ("nlb_sg_in", "Network load balancers", "Flows blocked by the security group coming in", "defence", "flows"),
    ("nlb_sg_out", "Network load balancers", "Flows blocked by the security group going out", "health", "flows"),
    ("nlb_elb_reset", "Network load balancers", "Connections reset by the load balancer", "health", "resets"),
    ("nlb_target_reset", "Network load balancers", "Connections reset by targets", "health", "resets"),
    ("nlb_tls", "Network load balancers", "TLS handshakes failed", "health", "handshakes"),
    ("alb_elb_4xx", "Application load balancers", "Requests refused by the load balancer (4xx)", "info", "requests"),
    ("alb_elb_5xx", "Application load balancers", "Load balancer errors (5xx)", "health", "requests"),
    ("alb_target_5xx", "Application load balancers", "Errors returned by targets (5xx)", "health", "requests"),
    ("alb_target_conn", "Application load balancers", "Connections to targets failed", "health", "connections"),
    (
        "alb_rejected",
        "Application load balancers",
        "Connections rejected at the connection limit",
        "health",
        "connections",
    ),
    ("alb_tls", "Application load balancers", "TLS handshakes failed", "health", "handshakes"),
    ("api_4xx", "API Gateway", "Requests refused (4xx)", "info", "requests"),
    ("api_5xx", "API Gateway", "Errors (5xx)", "health", "requests"),
    ("vpcs_rst", "PrivateLink", "Connections reset by this account's endpoint services", "health", "reset packets"),
    ("vpce_dropped", "PrivateLink", "Packets dropped at interface endpoints", "health", "packets"),
    ("db_login", "Databases", "Failed database sign-ins (Aurora MySQL)", "security", "sign-ins"),
    ("nat_unanswered", "NAT gateways", "Connections out with no response", "health", "connections"),
    ("nat_port", "NAT gateways", "Connections failed: no source port free", "health", "connections"),
    ("nat_drop", "NAT gateways", "Packets dropped", "health", "packets"),
    ("tgw_blackhole", "Transit gateways", "Packets dropped by blackhole routes", "health", "packets"),
    ("tgw_noroute", "Transit gateways", "Packets dropped with no route", "health", "packets"),
]
KIND_OF = {k: kind for k, _, _, kind, _ in CLASSES}
CLASS_WHAT = {k: what for k, _, what, _, _ in CLASSES}
CLASS_UNIT = {k: unit for k, *_, unit in CLASSES}
WHERE = {"internet": "The internet", "account": "Another account",
         "onprem": "Private network outside the scan (on premises)", "own": "Inside the account"}  # fmt: skip
WHERE_SHORT = {"internet": "the internet", "account": "another account", "onprem": "private networks outside the scan",
               "own": "inside the account"}  # fmt: skip
# How much each reason to look weighs, as in the other reports' risk points: recon that got traffic in is critical,
# other recon high, a failure new today medium, a fault (traffic that should have worked) low. A non-production
# account's points count a tenth.
SEVERITY = {"recon": "high", "new": "medium", "health": "low"}
NOT_MEASURED = (
    "Zero windows, retransmissions, duplicate ACKs and other TCP detail: flow logs record only accepted or "
    "rejected and the SYN, SYN-ACK, FIN and RST flags. A packet capture (VPC Traffic Mirroring) shows them.",
    "Timeouts on UDP, and TCP timeouts where the first SYN was answered later: only retried SYNs with no reply "
    "are counted.",
)


def _ip(a):
    try:
        return ipaddress.ip_address(a)
    except (ValueError, TypeError):
        return None


def _net(c):
    try:
        return ipaddress.ip_network(c, strict=False)
    except (ValueError, TypeError):
        return None


class CidrIndex:
    """Which scanned account owns an address: a lookup per prefix length, fast for many addresses."""

    def __init__(self) -> None:
        self.by_len: dict[tuple[int, int], dict[int, str]] = {}

    def add(self, net, owner: str) -> None:
        self.by_len.setdefault((net.version, net.prefixlen), {})[int(net.network_address)] = owner

    def owner(self, ip) -> str | None:
        best = None
        for (version, plen), nets in self.by_len.items():
            if version != ip.version or (best and plen <= best[0]):
                continue
            bits = 32 if version == 4 else 128
            key = int(ip) >> (bits - plen) << (bits - plen) if plen else 0
            if key in nets:
                best = (plen, nets[key])
        return best[1] if best else None


def _cidrs(f: dict) -> list:
    nets = []
    for x in (f.get("access_assets") or {}).values():
        nets += [n for v in x.get("vpcs") or [] for n in map(_net, v.get("cidrs") or []) if n]
    if not nets:
        nets = [n for x in (f.get("access_network") or {}).values() for n in map(_net, x.get("cidrs") or []) if n]
    return nets


def port_name(port) -> str:
    p = str(port or "")
    return f"{p} ({PORTS[p]})" if p in PORTS else p


def build_network_review(scan: dict, account_filter: AccountFilter | None = None, onprem: str = "",
                         answers=None) -> dict:  # fmt: skip
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    checked = (scan.get("assurance") or {}).get("accounts") or {}
    accounts = {a["id"]: a for a in scan.get("accounts") or []}
    names = {aid: a.get("name", "") for aid, a in accounts.items()}
    owners = {aid: owner_of(a) for aid, a in accounts.items()}
    base = {"scan_id": scan.get("id"), "where": WHERE, "not_measured": list(NOT_MEASURED),
            "classes": [{"key": k, "group": g, "what": w, "kind": kind, "unit": unit}
                        for k, g, w, kind, unit in CLASSES]}  # fmt: skip
    if not checked:
        return {
            **base,
            "available": False,
            "reason": "This scan has no Cloud Assurance checks: run a new scan with Cloud Assurance ticked.",
        }
    scanned = {aid: (r.get("facts") or {}) for aid, r in checked.items() if account_filter.matches(names.get(aid, aid))}
    index = CidrIndex()
    own: dict[str, list] = {}
    for aid, f in scanned.items():
        own[aid] = _cidrs(f)
        for n in own[aid]:
            index.add(n, aid)
    ranges = parse_ranges(onprem)
    for f in scanned.values():  # the ranges each VPN sends down its tunnel are on premises, named by the VPN
        for x in (f.get("access_assets") or {}).values():
            for v in x.get("vpns") or []:
                ranges += [(n, f"Behind VPN {v.get('name') or v['id']}") for n in map(_net, v.get("routes") or []) if n]
    who = _Who(names, owners, index, ranges)
    trail = _trail(scanned)
    seen = _Seen()
    rows, new_rows = [], []
    cov = {"accounts": len(scanned), "flows_read": 0, "tcp_read": 0, "baseline_read": 0, "baseline_full": 0,
           "s3_only": 0, "s3_accounts": 0, "no_flow_logs": 0, "no_flow_log_accounts": 0, "metrics_read": 0,
           "insights_bytes": 0, "trail_read": any((f.get("trail_denials") or {}).get("read")
                                                  for f in scanned.values())}  # fmt: skip
    for aid, f in scanned.items():
        row = _account(aid, f, own[aid], who, trail["counts"].get(aid), seen, new_rows, cov)
        row.update(who.account(aid))
        gap = (checked[aid].get("checks") or {}).get("flow_logs") or {}
        if gap.get("status") == "fail":
            row["no_flow_logs"] = gap.get("n") or len(gap.get("ev") or [])
            cov["no_flow_logs"] += row["no_flow_logs"]
            cov["no_flow_log_accounts"] += 1
        rows.append(row)
    links = _links(scanned, who)
    datacentre = _datacentre(scanned, own, who, rows)
    riskpoints.enrich(scan, rows, answers)
    for row in rows:  # every account is read before the reasons: recon is judged across the estate
        row["reasons"] = _reasons(row, seen, trail, who) + _link_reasons(row["id"], links)
        recon = sum(1 for r in row["reasons"] if r["kind"] == "recon")
        row["recon"] = bool(recon)
        row["attention"] = 1000 * recon + 10 * row["new_inside"] + (1 if row["reasons"] else 0)
        _risk(row)
        row["inside_sources"] = _inside_sources(row, who)
        del row["_ext"], row["_inside"], row["_by_class"]
    cov["insights_cost"] = round(cov["insights_bytes"] / 1e9 * INSIGHTS_PER_GB, 2)
    rows.sort(key=lambda r: (-r["attention"], -r["health"], -r["total"], r["name"]))
    look = [r for r in rows if r["reasons"]][:15]
    totals = _totals(rows)
    new_rows.sort(key=lambda r: (r["where"] == "internet" and r["dir"] == "in", -r["flows"]))
    log.info("network review: %d accounts, %d new failures in %.2fs", len(rows), len(new_rows),
             time.perf_counter() - started)  # fmt: skip
    return {
        **base,
        "available": True,
        "hours": 24,
        "base_days": next(
            (
                fl["baseline"]["days"]
                for f in scanned.values()
                for fl in (f.get("access_flows") or {}).values()
                if (fl.get("baseline") or {}).get("days")
            ),
            7,
        ),  # fmt: skip
        "coverage": cov,
        "totals": totals,
        "accounts": rows,
        "look": [
            {
                k: r[k]
                for k in (
                    "id",
                    "name",
                    "owner",
                    "executive",
                    "reasons",
                    "total",
                    "health",
                    "security",
                    "bytes",
                    "where",
                    "new_pairs",
                    "read",
                    "production",
                    "risk",
                    "rating",
                )
            }
            for r in look
        ],  # fmt: skip
        "new_today": new_rows[:NEW_ROWS],
        "new_count": len(new_rows),
        "sources": _sources(seen, who) + [s for r in rows for s in r.pop("inside_sources")],
        "links": links,
        "datacentre": datacentre,
        "internet": [
            {**{k: r[k] for k in ("id", "name", "owner", "executive")}, **r["internet"]}
            for r in rows
            if r["internet"]["bytes"] or r["internet"]["failed"]
        ],
    }


class _Who:
    """Names an address or an account: the account's name, owner and executive where tagged."""

    def __init__(self, names: dict, owners: dict, index: CidrIndex, ranges: list | None = None) -> None:
        self.names, self.owners, self.index, self.ranges = names, owners, index, ranges or []

    def account(self, aid: str | None) -> dict:
        if not aid:
            return {"id": "", "name": "", "owner": "", "executive": ""}
        owner, executive = self.owners.get(aid) or ("", "")
        return {"id": aid, "name": self.names.get(aid) or aid, "owner": owner, "executive": executive}

    def label(self, aid: str | None) -> str:
        a = self.account(aid)
        return f"{a['name']} (owner {a['owner']})" if a["owner"] else a["name"]

    def address(self, ip, own_nets: list | None = None) -> dict:
        """{where, account}: the internet, a scanned account (with its name and owner), this account, or a
        private network outside the scan."""
        if own_nets is not None and any(ip in n for n in own_nets):
            return {"where": "own", "account": None}
        if ip.is_global:
            return {"where": "internet", "account": None}
        owner = self.index.owner(ip)
        if owner:
            return {"where": "account", "account": self.account(owner)}
        named = max((r for r in self.ranges if ip.version == r[0].version and ip in r[0]),
                    key=lambda r: r[0].prefixlen, default=None)  # fmt: skip
        return {"where": "onprem", "account": None, "name": named[1] if named else ""}


class _Seen:
    """What each source did across the estate, for recon judged over every account."""

    def __init__(self) -> None:
        self.ext: dict[str, dict] = {}  # internet address: {account id: activity}
        self.accepted: dict[str, dict] = {}  # internet address: {account id: {flows, bytes, to}}

    def hit(self, ip: str, aid: str) -> dict:
        return self.ext.setdefault(ip, {}).setdefault(aid, _activity())


def _activity() -> dict:
    return {"ports": set(), "targets": set(), "flows": 0, "bytes": 0, "classes": {}, "new": False, "src_new": False,
            "seen_before": False}  # fmt: skip


def _trail(scanned: dict) -> dict:
    """CloudTrail refusals: counts per account, and per caller (account, who, ip) the calls and sign-ins."""
    counts: dict[str, dict] = {}
    callers: dict[tuple, dict] = {}
    for f in scanned.values():
        for r in (f.get("trail_denials") or {}).get("rows") or []:
            aid = r.get("account") or ""
            n = int(r.get("n") or 0)
            login = r.get("call") == "ConsoleLogin"
            x = counts.setdefault(aid, {"trail_denied": 0, "trail_login": 0})
            x["trail_login" if login else "trail_denied"] += n
            c = callers.setdefault((aid, r.get("who") or "", r.get("ip") or ""),
                                   {"calls": {}, "codes": set(), "logins": 0, "n": 0})  # fmt: skip
            if login:
                c["logins"] += n
            else:
                key = f"{(r.get('svc') or '').split('.')[0]}:{r.get('call')}"
                c["calls"][key] = c["calls"].get(key, 0) + n
                c["n"] += n
            if r.get("code"):
                c["codes"].add(r["code"])
    by_ip: dict[str, set] = {}
    for aid, _who, ip in callers:
        if ip:
            by_ip.setdefault(ip, set()).add(aid)
    return {"counts": counts, "callers": callers, "by_ip": by_ip}


def _account(aid, f, nets, who, trail, seen, new_rows, cov) -> dict:
    counts = {k: 0 for k, *_ in CLASSES}
    class_bytes = {k: 0 for k, *_ in CLASSES}
    resources: dict[str, list] = {}
    read = {"flows": False, "tcp": False, "baseline": False, "metrics": False}
    where = {k: 0 for k in WHERE}
    failed_bytes = new_pairs = new_sources = new_inside = 0
    top: list[dict] = []
    inside: dict[str, dict] = {}
    by_class: dict[str, list] = {}
    net = {"out_bytes": 0, "in_bytes": 0, "out_flows": 0, "in_flows": 0, "ips": 0, "exact": False, "read": False,
           "failed_out": 0, "refused_in": 0, "top": {}}  # fmt: skip
    for region, fl in (f.get("access_flows") or {}).items():
        _internet(net, fl, nets)
        cov["insights_bytes"] += int(fl.get("insights_bytes") or 0)
        cov["s3_only"] += len(fl.get("s3_only") or [])
        read["flows"] |= bool(fl.get("reject_covered"))
        read["tcp"] |= bool(fl.get("tcp_covered"))
        base = fl.get("baseline") or {}
        read["baseline"] |= bool(base.get("read"))
        if base.get("full"):
            read["baseline_full"] = True
        for r in fl.get("rows") or []:  # accepted: did anything from a probing address get through?
            src = _ip(r.get("src"))
            if src and src.is_global:
                x = seen.accepted.setdefault(str(src), {}).setdefault(aid, {"flows": 0, "bytes": 0, "to": set()})
                x["flows"] += int(r.get("flows") or 0)
                x["bytes"] += int(r.get("bytes") or 0)
                x["to"].add(f"{r.get('dst')}:{r.get('port')}")
        for kind, items in (("refused", fl.get("rejected") or []), ("tcp", fl.get("failed_tcp") or [])):
            for r in items:
                src, dst = _ip(r.get("src")), _ip(r.get("dst"))
                if not src or not dst:
                    continue
                s_own, d_own = any(src in n for n in nets), any(dst in n for n in nets)
                if s_own and d_own:
                    local, remote, direction = src, dst, "internal"
                else:
                    local, remote, direction = (src, dst, "out") if s_own else (dst, src, "in")
                far = who.address(remote, nets if direction == "internal" else None)
                if direction == "internal":
                    far = {"where": "own", "account": None}
                if kind == "tcp":
                    cls = r.get("kind") or "unanswered"
                elif direction == "internal":
                    cls = "refused_internal"
                elif direction == "out":
                    cls = "refused_out"
                else:
                    cls = "refused_in_internet" if far["where"] == "internet" else "refused_in_private"
                n, b = int(r.get("flows") or 0), int(r.get("bytes") or 0)
                counts[cls] += n
                class_bytes[cls] += b
                where[far["where"]] += n
                failed_bytes += b
                if far["where"] == "internet":
                    net["failed_out" if direction == "out" else "refused_in"] += n
                item = {"local": str(local), "remote": str(remote), "port": port_name(r.get("port")), "dir": direction,
                        "class": cls, "where": far["where"], "remote_account": (far["account"] or {}).get("name", ""),
                        "remote_owner": (far["account"] or {}).get("owner", ""), "remote_name": far.get("name", ""),
                        "flows": n, "bytes": b,
                        "packets": int(r.get("packets") or 0), "region": region, "new": r.get("new"),
                        "src_new": r.get("src_new")}  # fmt: skip
                top.append(item)
                by_class.setdefault(cls, []).append(item)
                if r.get("new"):
                    new_pairs += 1
                    if r.get("src_new"):
                        new_sources += 1
                    if not (far["where"] == "internet" and direction == "in"):
                        new_inside += 1
                    a = who.account(aid)
                    new_rows.append({**item, "account": aid, "account_name": a["name"], "account_owner": a["owner"]})
                port = str(r.get("port") or "")
                if src.is_global and not dst.is_global:
                    x = seen.hit(str(src), aid)
                elif not src.is_global and port:  # a scan from inside the estate
                    x = inside.setdefault(str(src), _activity())
                else:
                    continue
                if port:
                    x["ports"].add(port)
                x["targets"].add(str(dst))
                x["flows"] += n
                x["bytes"] += b
                x["classes"][cls] = x["classes"].get(cls, 0) + n
                x["new"] |= r.get("new") is True
                x["src_new"] |= r.get("src_new") is True
                x["seen_before"] |= r.get("src_new") is False
    for region, x in (f.get("access_failures") or {}).items():
        if "metrics" not in x:
            continue
        read["metrics"] = True
        for key, v in x["metrics"].items():
            cat = FAIL_METRIC_CAT.get(key, key)
            if cat in counts and v.get("total"):
                counts[cat] += int(v["total"])
                resources.setdefault(cat, []).extend(
                    {"name": name, "region": region, "count": int(val)} for name, val in v.get("top") or []
                )
    for k, v in (trail or {}).items():
        counts[k] += v
    for k in ("flows", "tcp", "baseline", "metrics"):
        cov[f"{k}_read"] += 1 if read[k] else 0
    cov["baseline_full"] += 1 if read.get("baseline_full") else 0
    if any(fl.get("s3_only") for fl in (f.get("access_flows") or {}).values()):
        cov["s3_accounts"] += 1
    for v in resources.values():
        v.sort(key=lambda r: -r["count"])
    for v in by_class.values():
        v.sort(key=lambda r: -r["flows"])
    health = sum(v for k, v in counts.items() if KIND_OF[k] == "health")
    security = sum(v for k, v in counts.items() if KIND_OF[k] == "security")
    total = sum(v for k, v in counts.items() if KIND_OF[k] != "info")
    top.sort(key=lambda r: (-(r["new"] is True), r["class"] in ("refused_in_internet", "reset"), -r["flows"]))
    return {"id": aid, "read": read, "counts": counts, "class_bytes": class_bytes, "where": where,
            "bytes": failed_bytes, "health": health, "security": security, "total": total, "new_pairs": new_pairs,
            "new_sources": new_sources, "new_inside": new_inside, "top": top[:TOP],
            "resources": {k: v[:TOP] for k, v in resources.items()}, "internet": _internet_row(net),
            "_ext": aid, "_inside": inside, "_by_class": by_class}  # fmt: skip


def _internet(net: dict, fl: dict, nets: list) -> None:
    """Traffic with the internet in one region: the totals the flow-log query counted (every connection of the
    day), or else what the largest conversations read show (a floor). Top destinations come from those."""
    if fl.get("covered"):
        net["read"] = True
    exact = fl.get("internet")
    if exact:
        net["exact"] = True
        for d in ("out", "in"):
            net[f"{d}_bytes"] += int(exact[d].get("bytes") or 0)
            net[f"{d}_flows"] += int(exact[d].get("flows") or 0)
        net["ips"] += int(exact["out"].get("ips") or 0)
    seen = set()
    for r in fl.get("rows") or []:
        src, dst = _ip(r.get("src")), _ip(r.get("dst"))
        if not src or not dst:
            continue
        n, b = int(r.get("flows") or 0), int(r.get("bytes") or 0)
        if dst.is_global and not src.is_global:
            d = "out"
            t = net["top"].setdefault(str(dst), {"ip": str(dst), "bytes": 0, "flows": 0, "ports": set()})
            t["bytes"] += b
            t["flows"] += n
            t["ports"].add(port_name(r.get("port")))
            seen.add(str(dst))
        elif src.is_global and not dst.is_global:
            d = "in"
        else:
            continue
        if not exact:
            net[f"{d}_bytes"] += b
            net[f"{d}_flows"] += n
    if not exact:
        net["ips"] += len(seen)


def _internet_row(net: dict) -> dict:
    top = sorted(net.pop("top").values(), key=lambda t: -t["bytes"])[:5]
    for t in top:
        t["ports"] = sorted(t["ports"])[:4]
    return {
        **net,
        "bytes": net["out_bytes"] + net["in_bytes"],
        "failed": net["failed_out"] + net["refused_in"],
        "top": top,
    }


def _ports(ports) -> str:
    ps = sorted(ports, key=lambda p: int(p) if p.isdigit() else 0)
    shown = ", ".join(port_name(p) for p in ps[:12])
    return shown + (f" and {len(ps) - 12} more" if len(ps) > 12 else "")


def _addrs(addrs, most: int = 8) -> str:
    a = sorted(addrs)
    return ", ".join(a[:most]) + (f" and {len(a) - most} more" if len(a) > most else "")


def _size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1024
    return ""


def _first_seen(x: dict) -> str:
    if x["src_new"]:
        return "New today: this address had not failed anywhere here in the days before"
    if x["new"]:
        return "New today at these targets; it failed elsewhere here before"
    if x["seen_before"]:
        return "Not new: it failed here in the days before too"
    return "Not compared (the days before were not read)"


def _reasons(row: dict, seen: _Seen, trail: dict, who: _Who) -> list[dict]:
    aid = row["id"]
    reasons: list[dict] = []
    # Recon from the internet: an address refused on many ports or addresses, or in several accounts.
    mine = [(ip, accts[aid]) for ip, accts in seen.ext.items() if aid in accts]
    for ip, x in sorted(mine, key=lambda kv: (-len(seen.ext[kv[0]]), -len(kv[1]["ports"]), -kv[1]["flows"])):
        others = [a for a in seen.ext[ip] if a != aid]
        if not (len(x["ports"]) >= SWEEP or len(x["targets"]) >= SWEEP or others):
            continue
        estate = sum(v["flows"] for v in seen.ext[ip].values())
        got_in = seen.accepted.get(ip, {})
        api = sorted(trail["by_ip"].get(ip, set()))
        facts = [
            ["Source", f"{ip}, on the internet"],
            ["Refused here", f"{x['flows']:,} connections, {_size(x['bytes'])}"],
            ["Ports tried", _ports(x["ports"])],
            ["Addresses it tried here", _addrs(x["targets"])],
            ["Also refused in", "; ".join(f"{who.label(a)}: {seen.ext[ip][a]['flows']:,} connections"
                                          for a in others) or "No other account"],
            ["Across the estate", f"{estate:,} connections in {len(seen.ext[ip])} "
                                  f"account{'s' if len(seen.ext[ip]) != 1 else ''}"],
            ["First seen", _first_seen(x)],
        ]  # fmt: skip
        if api:
            facts.append(
                [
                    "Also refused at the API",
                    f"calls from this address refused in {', '.join(who.label(a) for a in api)}",
                ]
            )
        if got_in:
            facts.append(["Let in", "; ".join(f"{who.label(a)}: {v['flows']:,} connections, {_size(v['bytes'])} to "
                                              f"{_addrs(v['to'], 4)}" for a, v in got_in.items())])  # fmt: skip
        else:
            facts.append(["Let in", "Nothing from this address among the largest accepted conversations read"])
        what = [f"{len(x['ports'])} ports" if len(x["ports"]) > 1 else f"port {_ports(x['ports'])}",
                f"{len(x['targets'])} addresses" if len(x["targets"]) > 1 else ""]  # fmt: skip
        text = f"{ip} on the internet: {x['flows']:,} connections refused on {', '.join(w for w in what if w)}" + (
            f", also in {', '.join(who.account(a)['name'] for a in others)}" if others else ""
        )
        reasons.append({"kind": "recon", "text": text, "facts": facts, "severity": "critical" if got_in else "high",
                        "means": "Someone is mapping the estate: trying ports and addresses to find a way in.",
                        "do": ("Traffic from this address was let in: check what it reached and from where, now."
                               if got_in else "The security groups held. Block the address at the WAF or network "
                               "firewall if it keeps on, and check no security group opens these ports to the "
                               "internet.")})  # fmt: skip
    # Recon at the API: one caller refused on many calls, or many failed sign-ins.
    for (acct, caller, ip), c in sorted(
        trail["callers"].items(), key=lambda kv: (-len(kv[1]["calls"]), -kv[1]["logins"])
    ):
        if acct != aid or not (len(c["calls"]) >= ENUM or c["logins"] >= LOGINS):
            continue
        short = caller.rsplit("/", 1)[-1] or caller or "unknown caller"
        src = _ip(ip)
        place = who.address(src) if src else None
        origin = ("" if not src else f"{ip}, on the internet" if place["where"] == "internet"
                  else f"{ip}, in {who.label(place['account']['id'])}" if place["where"] == "account"
                  else f"{ip}, a private network outside the scan")  # fmt: skip
        elsewhere = sorted(
            a for (a2, w2, i2) in trail["callers"] for a in [a2] if w2 == caller and i2 == ip and a != aid
        )
        net = ip in seen.ext
        facts = [["Caller", caller or "unknown"], ["From", origin or "not recorded"]]
        if c["calls"]:
            calls = sorted(c["calls"].items(), key=lambda kv: -kv[1])
            facts += [["Refused", f"{c['n']:,} calls, {len(calls)} different"],
                      ["Calls", ", ".join(f"{k} ({v:,})" for k, v in calls[:12])
                       + (f" and {len(calls) - 12} more" if len(calls) > 12 else "")],
                      ["Why refused", ", ".join(sorted(c["codes"])) or "not recorded"]]  # fmt: skip
        if c["logins"]:
            facts.append(["Failed console sign-ins", f"{c['logins']:,}"])
        if elsewhere:
            facts.append(["Also refused in", ", ".join(who.label(a) for a in elsewhere)])
        if net:
            facts.append(["Also refused at the network", f"in {', '.join(who.label(a) for a in seen.ext[ip])}"])
        if len(c["calls"]) >= ENUM:
            reasons.append({"kind": "recon", "facts": facts,
                            "text": f"{short}{f' from {ip}' if ip else ''}: refused on {len(c['calls'])} different API "
                                    f"calls ({c['n']:,} in all)",
                            "means": "A credential being tried against many services to see what it can do: a stolen "
                                     "key, or a tool given too little access.",
                            "do": "Ask the owner whether this caller and address are known. If not, disable the key "
                                  "or session and check what it did that was allowed."})  # fmt: skip
        if c["logins"] >= LOGINS:
            root = short == "root" or caller.endswith(":root")
            reasons.append({"kind": "recon", "facts": facts,
                            "text": f"{c['logins']:,} failed console sign-ins by {short}{f' from {ip}' if ip else ''}",
                            "means": "Someone guessing a password" + (" for the root user." if root else "."),
                            "do": ("Check the root user has MFA and no access keys; " if root else "")
                                  + "confirm with the owner whether the sign-ins were theirs."})  # fmt: skip
    # A sweep from inside the estate.
    for ip, x in sorted(row["_inside"].items(), key=lambda kv: -len(kv[1]["ports"])):
        if len(x["ports"]) < INTERNAL_SWEEP:
            continue
        place = who.address(_ip(ip))
        src_at = (who.label(place["account"]["id"]) if place["where"] == "account"
                  else "a private network outside the scan (on premises, or an account not scanned)")  # fmt: skip
        if place["account"] and place["account"]["id"] == aid:
            src_at = "this account"
        kinds = ", ".join(f"{CLASS_WHAT[k].split(':')[0].lower()} {v:,}" for k, v in
                          sorted(x["classes"].items(), key=lambda kv: -kv[1]))  # fmt: skip
        reasons.append({"kind": "recon", "facts": [
            ["Source", f"{ip}, in {src_at}"], ["Ports tried", _ports(x["ports"])],
            ["Addresses it tried", _addrs(x["targets"])],
            ["Failed", f"{x['flows']:,} connections, {_size(x['bytes'])}: {kinds}"],
            ["First seen", _first_seen(x)]],
            "text": f"{ip}, inside the estate in {src_at}, failed on {len(x['ports'])} ports at "
                    f"{len(x['targets'])} address{'es' if len(x['targets']) != 1 else ''}",
            "means": "A port scan from inside: a compromised host mapping its neighbours, a security scanner, or "
                     "a client misconfigured.",
            "do": "Ask the owner of the source whether it runs a scanner. If not, isolate the host and look at what "
                  "it ran."})  # fmt: skip
    # New today, inside the estate and going out.
    fresh = [
        r
        for k, v in row["_by_class"].items()
        for r in v
        if r["new"] is True and not (r["where"] == "internet" and r["dir"] == "in")
    ]
    if fresh:
        fresh.sort(key=lambda r: -r["flows"])
        reasons.append({"kind": "new", "rows": fresh[:10],
                        "text": f"{len(fresh)} source and target pairs failing today that did not fail in the days "
                                f"before ({sum(r['flows'] for r in fresh):,} connections, "
                                f"{_size(sum(r['bytes'] for r in fresh))}), not counting the internet knocking",
                        "means": "Something changed today: a new client, a changed rule or route, or a host reaching "
                                 "somewhere it never did.",
                        "do": "Check each with the owner against today's changes; one nobody expects is the first "
                              "sign of a compromise."})  # fmt: skip
    # Traffic that should have worked.
    for cls, label, means in (
        ("refused_out", "connections refused going out", "A security group or network ACL stops this account "
                                                          "reaching something it tries to reach."),
        ("refused_internal", "connections refused inside the account", "Two parts of the same account cannot "
                                                                        "talk: a rule missing or wrong."),
        ("unanswered", "connection attempts timed out", "Sent and never answered: the target is down, a route or "
                                                        "firewall drops it silently, or the address is wrong."),
    ):  # fmt: skip
        flows = row["_by_class"].get(cls) or []
        if not row["counts"][cls]:
            continue
        reasons.append({"kind": "health", "rows": flows[:10],
                        "text": f"{row['counts'][cls]:,} {label}, {_size(row['class_bytes'][cls])}"
                                + _to_where(flows, who),
                        "means": means, "do": "Ask the owner whether the traffic should work; fix the rule or "
                                              "route, or stop the client trying."})  # fmt: skip
    for cls, label, means in (
        ("nat_unanswered", "connections out through NAT with no response", "Outbound connections that got no "
         "reply: the far end is down or drops them, or a firewall in between does."),
        ("nat_port", "connections out through NAT failed: no source port free", "The NAT gateway ran out of "
         "ports to one destination: too many connections at once to the same address and port."),
        ("tgw_blackhole", "packets dropped by transit gateway blackhole routes", "Traffic sent to a route that "
         "is switched off: a network change left behind, or a block on purpose."),
        ("tgw_noroute", "packets dropped by the transit gateway with no route", "Traffic for a network the "
         "transit gateway has no route to."),
        ("alb_target_conn", "connections from load balancers to targets failed", "The load balancer could not "
         "reach its targets: unhealthy hosts, or a security group in between."),
    ):  # fmt: skip
        if not row["counts"][cls]:
            continue
        res = row["resources"].get(cls) or []
        reasons.append({"kind": "health", "means": means, "do": "Ask the owner of the resources named.",
                        "text": f"{row['counts'][cls]:,} {label}" + (f", at {res[0]['name']}" if len(res) == 1 else
                                                                      f", at {len(res)} resources" if res else ""),
                        "facts": [[r["name"], f"{r['count']:,} {CLASS_UNIT[cls]} ({r['region']})"]
                                  for r in res]})  # fmt: skip
    return reasons


def _risk(row: dict) -> None:
    """The account's risk points and rating from its reasons to look, for the bubble charts."""
    for r in row["reasons"]:
        r.setdefault("severity", SEVERITY.get(r["kind"], "low"))
    riskpoints.score(row, {k: sum(1 for r in row["reasons"] if r["severity"] == k) for k in riskpoints.POINTS})


def _to_where(flows: list[dict], who: _Who) -> str:
    by: dict[str, int] = {}
    for r in flows:
        key = f"{r['remote_account']}" if r["where"] == "account" else WHERE_SHORT[r["where"]]
        by[key] = by.get(key, 0) + r["flows"]
    parts = sorted(by.items(), key=lambda kv: -kv[1])
    return ("" if not parts else ", to " + ", ".join(f"{k} ({v:,})" for k, v in parts[:3])
            + (f" and {len(parts) - 3} more" if len(parts) > 3 else ""))  # fmt: skip


def _totals(rows: list[dict]) -> dict:
    classes = []
    for k, group, what, kind, unit in CLASSES:
        hit = [r for r in rows if r["counts"][k]]
        worst = max(hit, key=lambda r: r["counts"][k], default=None)
        classes.append({"key": k, "group": group, "what": what, "kind": kind, "unit": unit,
                        "count": sum(r["counts"][k] for r in rows), "bytes": sum(r["class_bytes"][k] for r in rows),
                        "accounts": len(hit),
                        "worst": {"id": worst["id"], "name": worst["name"], "owner": worst["owner"],
                                  "count": worst["counts"][k]} if worst else None})  # fmt: skip
    return {
        "classes": classes,
        "failed": sum(r["total"] for r in rows),
        "health": sum(r["health"] for r in rows),
        "security": sum(r["security"] for r in rows),
        "bytes": sum(r["bytes"] for r in rows),
        "where": {k: sum(r["where"][k] for r in rows) for k in WHERE},
        "accounts_failing": sum(1 for r in rows if r["total"]),
        "recon_accounts": sum(1 for r in rows if r["recon"]),
        "new_pairs": sum(r["new_pairs"] for r in rows),
        "new_sources": sum(r["new_sources"] for r in rows),
        "new_inside": sum(r["new_inside"] for r in rows),
    }


def _sources(seen: _Seen, who: _Who) -> list[dict]:
    """Internet addresses refused or unanswered in the estate, the widest first: in several accounts, or on
    many ports or addresses, is someone mapping it."""
    out = []
    for ip, accts in seen.ext.items():
        ports = set().union(*(x["ports"] for x in accts.values()))
        targets = set().union(*(x["targets"] for x in accts.values()))
        got_in = seen.accepted.get(ip, {})
        out.append({"ip": ip, "internal": False, "where": "internet",
                    "accounts": [{**who.account(a), "flows": x["flows"]} for a, x in accts.items()],
                    "attempts": sum(x["flows"] for x in accts.values()),
                    "bytes": sum(x["bytes"] for x in accts.values()),
                    "ports": [port_name(p) for p in sorted(ports, key=lambda p: int(p) if p.isdigit() else 0)[:12]],
                    "port_count": len(ports), "targets": len(targets), "target_list": sorted(targets)[:12],
                    "recon": len(accts) > 1 or len(ports) >= SWEEP or len(targets) >= SWEEP,
                    "new": any(x["src_new"] for x in accts.values()),
                    "let_in": [{**who.account(a), "flows": v["flows"], "bytes": v["bytes"]}
                               for a, v in got_in.items()]})  # fmt: skip
    out.sort(key=lambda x: (-len(x["accounts"]), -x["port_count"], -x["attempts"]))
    return out[:SOURCES]


# ---------------------------------------------------------------- the links and the data centre


def _bps(text: str) -> float:
    """'10Gbps' or '500Mbps' as bits a second; 0 when unknown."""
    m = re.fullmatch(r"\s*([\d.]+)\s*([GMK])bps\s*", text or "", re.I)
    return float(m.group(1)) * {"G": 1e9, "M": 1e6, "K": 1e3}[m.group(2).upper()] if m else 0.0


def _v(x: dict, key: str, stat: str = "sum") -> float:
    return float((x.get(key) or {}).get(stat) or 0)


def _hours(x: dict, key: str) -> list:
    return [v for _, v in (x.get(key) or {}).get("hours") or []]


def _flag(kind: str, text: str) -> dict:
    return {"kind": kind, "text": text}


def _links(scanned: dict, who: _Who) -> dict:
    atts: dict[str, dict] = {}
    vpns: dict[str, dict] = {}
    vifs: dict[str, dict] = {}
    nats: dict[str, dict] = {}
    services: dict[str, dict] = {}
    for aid, f in scanned.items():
        for region, x in (f.get("access_network") or {}).items():
            for a in x.get("tgw_attachments") or []:
                atts.setdefault(a["id"], {**a, "region": region})
            for s in x.get("services") or []:
                services[s["id"]] = {**s, "account": aid, "region": region}
        for region, x in (f.get("access_assets") or {}).items():
            for v in x.get("vpns") or []:
                vpns[v["id"]] = {**v, "account": aid, "region": region}
            for v in x.get("dx_vifs") or []:
                vifs[v["id"]] = {**v, "account": aid}
            for n in x.get("nats") or []:
                nats[n["id"]] = {**n, "account": aid, "region": region}
    out: dict = {"tgw": [], "dx": [], "vpn": [], "nat": [], "pl_services": [], "pl_endpoints": []}
    dx_seen = 0
    for aid, f in scanned.items():
        for region, x in (f.get("access_failures") or {}).items():
            links = x.get("links") or {}
            conns = {c["id"]: c for c in x.get("dx") or []}
            dx_seen += len(conns)
            # transit gateways, and each attachment's traffic and drops
            by_tgw: dict[str, list] = {}
            for label, m in (links.get("tgwa") or {}).items():
                tgw, _, att = label.partition("|")
                meta = atts.get(att) or {}
                hole, noroute = _v(m, "tgwa_hole"), _v(m, "tgwa_noroute")
                row = {"id": att, "type": meta.get("type", ""), "resource": meta.get("resource", ""),
                       "account": who.account(meta.get("owner")) if meta.get("owner") else None,
                       "bytes_in": _v(m, "tgwa_in"), "bytes_out": _v(m, "tgwa_out"), "hole": hole,
                       "noroute": noroute, "flags": []}  # fmt: skip
                if hole or noroute:
                    drop = f"{hole + noroute:,.0f} packets dropped ({hole:,.0f} blackhole, {noroute:,.0f} no route)"
                    row["flags"].append(_flag("health", drop))
                if not row["bytes_in"] and not row["bytes_out"]:
                    row["flags"].append(_flag("info", "Carried nothing in the last day"))
                by_tgw.setdefault(tgw, []).append(row)
            for tgw, m in (links.get("tgw") or {}).items():
                hole, noroute = _v(m, "tgw_hole"), _v(m, "tgw_noroute")
                rows = sorted(by_tgw.get(tgw, []), key=lambda r: -(r["hole"] + r["noroute"]) or -r["bytes_in"])
                flags = []
                if hole or noroute:
                    worst = [r for r in rows if r["hole"] or r["noroute"]][:3]
                    flags.append(_flag("health", f"{hole + noroute:,.0f} packets dropped in the last day ("
                                                 f"{hole:,.0f} to blackhole routes, {noroute:,.0f} with no route)"
                                                 + (", from " + ", ".join(_att_name(r) for r in worst)
                                                    if worst else "")))  # fmt: skip
                idle = [r for r in rows if not r["bytes_in"] and not r["bytes_out"]]
                if idle:
                    flags.append(_flag("info", f"{len(idle)} attachment{'s' if len(idle) != 1 else ''} carried "
                                               "nothing in the last day"))  # fmt: skip
                out["tgw"].append({"id": tgw, "account": who.account(aid), "region": region,
                                   "bytes_in": _v(m, "tgw_in"), "bytes_out": _v(m, "tgw_out"), "hole": hole,
                                   "noroute": noroute, "hours_in": _hours(m, "tgw_in"),
                                   "hours_out": _hours(m, "tgw_out"), "attachments": rows, "flags": flags})  # fmt: skip
            # Direct Connect connections and their virtual interfaces
            vif_rows: dict[str, list] = {}
            for label, m in (links.get("vif") or {}).items():
                conn, _, vif = label.partition("|")
                meta = vifs.get(vif) or {}
                vif_rows.setdefault(conn, []).append({"id": vif, "name": meta.get("name", ""),
                                                      "type": meta.get("type", ""), "state": meta.get("state", ""),
                                                      "peak_in": _v(m, "vif_in", "max"),
                                                      "peak_out": _v(m, "vif_out", "max")})  # fmt: skip
            for cid in sorted(set(links.get("dx") or {}) | set(conns)):
                m = (links.get("dx") or {}).get(cid) or {}
                c = conns.get(cid) or {}
                speed = _bps(c.get("bandwidth", ""))
                peak = max(_v(m, "dx_in_max", "max"), _v(m, "dx_out_max", "max"))
                state = _hours(m, "dx_state")
                down = sum(1 for v in state if v < 1)
                errs, crc = _v(m, "dx_err"), _v(m, "dx_crc")
                flags = []
                if c.get("state") and c["state"] != "available":
                    flags.append(_flag("health", f"The connection is {c['state']}"))
                if down:
                    flags.append(
                        _flag(
                            "health",
                            f"Down in {down} of the last {len(state)} hours"
                            + (" and down now" if state and state[-1] < 1 else ""),
                        )
                    )
                if errs or crc:
                    flags.append(_flag("health", f"{errs:,.0f} errors and {crc:,.0f} CRC errors on the line: "
                                                 "a fibre, optic or port fault"))  # fmt: skip
                if speed and peak >= 0.8 * speed:
                    flags.append(_flag("health", f"Peaked at {peak / speed:.0%} of its {c['bandwidth']}: near full"))
                out["dx"].append({"id": cid, "name": c.get("name", ""), "location": c.get("location", ""),
                                  "bandwidth": c.get("bandwidth", ""), "state": c.get("state", ""),
                                  "partner": c.get("partner", ""), "account": who.account(aid), "region": region,
                                  "peak_in": _v(m, "dx_in_max", "max"), "peak_out": _v(m, "dx_out_max", "max"),
                                  "avg_in": _avg(m, "dx_in"), "avg_out": _avg(m, "dx_out"),
                                  "peak_pct": round(peak / speed * 100, 1) if speed else None, "down_hours": down,
                                  "errors": errs, "crc": crc,
                                  "light_min": (m.get("dx_light") or {}).get("min"),
                                  "hours_in": _hours(m, "dx_in"), "hours_out": _hours(m, "dx_out"),
                                  "hours_state": state, "vifs": vif_rows.get(cid, []), "flags": flags})  # fmt: skip
            # VPN tunnels
            tunnels: dict[str, list] = {}
            for label, m in (links.get("vpn") or {}).items():
                vid, _, ip = label.partition("|")
                state = _hours(m, "vpn_state")
                tunnels.setdefault(vid, []).append({"ip": ip, "down_hours": sum(1 for v in state if v < 1),
                                                    "up_now": bool(state) and state[-1] >= 1, "hours": len(state),
                                                    "bytes_in": _v(m, "vpn_in"), "bytes_out": _v(m, "vpn_out"),
                                                    "hours_state": state})  # fmt: skip
            for vid in sorted(set(tunnels) | {v for v, meta in vpns.items()
                                             if meta["account"] == aid and meta["region"] == region}):  # fmt: skip
                meta = vpns.get(vid) or {}
                ts = tunnels.get(vid, [])
                total = meta.get("tunnels") or len(ts)
                up = meta.get("up") if "up" in meta else sum(1 for t in ts if t["up_now"])
                flags = []
                if total and up < total:
                    flags.append(
                        _flag(
                            "health", f"{up} of {total} tunnels up: " + ("no path left" if not up else "no second path")
                        )
                    )
                flaps = [t for t in ts if t["down_hours"] and t["up_now"]]
                if flaps:
                    flags.append(_flag("health", f"{len(flaps)} tunnel{'s' if len(flaps) != 1 else ''} went down in "
                                                 "the last day and came back"))  # fmt: skip
                out["vpn"].append({"id": vid, "name": meta.get("name", ""), "account": who.account(aid),
                                   "region": region, "gateway": meta.get("gateway", ""),
                                   "customer_ip": meta.get("customer_ip", ""), "routes": meta.get("routes") or [],
                                   "up": up, "total": total, "tunnels": ts,
                                   "bytes_in": sum(t["bytes_in"] for t in ts),
                                   "bytes_out": sum(t["bytes_out"] for t in ts), "flags": flags})  # fmt: skip
            # NAT gateways
            for nid, m in (links.get("nat") or {}).items():
                meta = nats.get(nid) or {}
                tried, made = _v(m, "nat_try"), _v(m, "nat_made")
                lost = max(tried - made, 0)
                ports, drops, idle = _v(m, "nat_port"), _v(m, "nat_drop"), _v(m, "nat_idle")
                flags = []
                if lost >= 100 and tried and lost / tried >= 0.05:
                    flags.append(_flag("health", f"{lost:,.0f} of {tried:,.0f} connections out ({lost / tried:.0%}) "
                                                 "got no response"))  # fmt: skip
                if ports:
                    flags.append(_flag("health", f"{ports:,.0f} connections failed: no source port free (more than "
                                                 "55,000 at once to one destination)"))  # fmt: skip
                if drops:
                    flags.append(_flag("health", f"{drops:,.0f} packets dropped by the NAT gateway"))
                out["nat"].append({"id": nid, "account": who.account(aid), "region": region,
                                   "vpc": meta.get("vpc", ""), "type": meta.get("type", ""),
                                   "public_ip": meta.get("public_ip", ""), "tried": tried, "made": made,
                                   "unanswered": lost, "unanswered_pct": round(lost / tried * 100, 1) if tried else 0,
                                   "port_errors": ports, "drops": drops, "idle_timeouts": idle,
                                   "peak_active": _v(m, "nat_active", "max"), "bytes_out": _v(m, "nat_out"),
                                   "bytes_in": _v(m, "nat_in"), "hours_tried": _hours(m, "nat_try"),
                                   "hours_made": _hours(m, "nat_made"), "flags": flags})  # fmt: skip
            # PrivateLink: services this account offers, and the endpoints it connects through
            consumers: dict[str, list] = {}
            for label, m in (links.get("vpcse") or {}).items():
                sid, _, ep = label.partition("|")
                consumers.setdefault(sid, []).append({"endpoint": ep, "bytes": _v(m, "vpcse_bytes"),
                                                      "rst": _v(m, "vpcse_rst")})  # fmt: skip
            for sid, m in (links.get("vpcs") or {}).items():
                meta = services.get(sid) or {}
                rst = _v(m, "vpcs_rst")
                flags = []
                if rst:
                    hit = sorted((c for c in consumers.get(sid, []) if c["rst"]), key=lambda c: -c["rst"])
                    flags.append(_flag("health", f"{rst:,.0f} reset packets sent to consumers: connections refused "
                                                 "or cut by the service's load balancer or targets"
                                                 + (f", most to {hit[0]['endpoint']}" if hit else "")))  # fmt: skip
                out["pl_services"].append({"id": sid, "name": meta.get("name", ""), "account": who.account(aid),
                                           "region": region, "allowed": meta.get("allowed") or [],
                                           "acceptance": meta.get("acceptance"),
                                           "endpoints": _v(m, "vpcs_eps", "max"), "bytes": _v(m, "vpcs_bytes"),
                                           "connections": _v(m, "vpcs_new"), "rst": rst,
                                           "consumers": sorted(consumers.get(sid, []), key=lambda c: -c["bytes"])[:20],
                                           "flags": flags})  # fmt: skip
            for label, m in (links.get("vpce") or {}).items():
                ep, svc, vpc = (label.split("|") + ["", "", ""])[:3]
                drop, rst = _v(m, "vpce_drop"), _v(m, "vpce_rst")
                flags = []
                if drop:
                    flags.append(_flag("health", f"{drop:,.0f} packets dropped at the endpoint"))
                if rst:
                    flags.append(_flag("health", f"{rst:,.0f} reset packets received from the service: connections "
                                                 "refused or cut at the far end"))  # fmt: skip
                owner = next((s["account"] for s in services.values() if s.get("name") == svc), None)
                out["pl_endpoints"].append({"id": ep, "service": svc, "vpc": vpc, "account": who.account(aid),
                                            "region": region,
                                            "provider": who.account(owner) if owner else None,
                                            "bytes": _v(m, "vpce_bytes"), "connections": _v(m, "vpce_new"),
                                            "drops": drop, "rst": rst, "flags": flags})  # fmt: skip
    scanned_ids = set(scanned)
    outside: dict[str, dict] = {}
    for a in atts.values():
        if a.get("tgw_owner") and a["tgw_owner"] not in scanned_ids:
            x = outside.setdefault(a["tgw"], {"id": a["tgw"], "owner": a["tgw_owner"], "accounts": set()})
            if a.get("owner"):
                x["accounts"].add(a["owner"])
    if dx_seen == 1 and not out["vpn"]:
        out["dx"][0]["flags"].append(_flag("health", "The only Direct Connect connection read, with no VPN beside "
                                                     "it: one fault cuts the data centre off"))  # fmt: skip
    for k in out:
        out[k].sort(key=lambda r: (-sum(1 for f in r["flags"] if f["kind"] == "health"), r["account"]["name"]))
    out["tgw_outside"] = [{"id": x["id"], "owner": x["owner"],
                           "accounts": [who.account(a) for a in sorted(x["accounts"])]}
                          for x in outside.values()]  # fmt: skip
    out["summary"] = {k: {"count": len(v), "flagged": sum(1 for r in v if any(f["kind"] == "health"
                                                                              for f in r["flags"]))}
                      for k, v in out.items() if k != "tgw_outside"}  # fmt: skip
    return out


def _avg(m: dict, key: str) -> float:
    x = m.get(key) or {}
    return round(x["sum"] / x["n"], 2) if x.get("n") else 0.0


def _att_name(r: dict) -> str:
    acct = (r.get("account") or {}).get("name")
    return f"{r['id']} ({r.get('type') or 'attachment'}{f' of {acct}' if acct else ''})"


def _datacentre(scanned: dict, own: dict, who: _Who, rows: list[dict]) -> dict:
    """Traffic between the scanned accounts and private networks outside them (on premises): what was let
    through, from the largest accepted conversations the flow logs gave, and what failed."""
    accts: dict[str, dict] = {}
    remote: dict[str, dict] = {}
    for aid, f in scanned.items():
        nets = own[aid]
        for region, fl in (f.get("access_flows") or {}).items():
            for r in fl.get("rows") or []:
                src, dst = _ip(r.get("src")), _ip(r.get("dst"))
                if not src or not dst:
                    continue
                s_own, d_own = any(src in n for n in nets), any(dst in n for n in nets)
                if s_own == d_own:
                    continue
                local, far, out = (src, dst, True) if s_own else (dst, src, False)
                place = who.address(far)
                if place["where"] != "onprem":
                    continue
                n, b = int(r.get("flows") or 0), int(r.get("bytes") or 0)
                a = accts.setdefault(aid, {**who.account(aid), "bytes_out": 0, "bytes_in": 0, "flows": 0,
                                           "failed": 0, "failed_by": {}})  # fmt: skip
                a["bytes_out" if out else "bytes_in"] += b
                a["flows"] += n
                key = (str(far), str(r.get("port")), aid, "out" if out else "in")
                x = remote.setdefault(key, {"remote": str(far), "remote_name": place.get("name", ""),
                                            "port": port_name(r.get("port")), "account": who.account(aid),
                                            "local": set(), "dir": "out" if out else "in", "bytes": 0,
                                            "flows": 0, "region": region})  # fmt: skip
                x["local"].add(str(local))
                x["bytes"] += b
                x["flows"] += n
    for row in rows:
        failed = [r for v in row["_by_class"].values() for r in v if r["where"] == "onprem"]
        if not failed:
            continue
        a = accts.setdefault(row["id"], {**who.account(row["id"]), "bytes_out": 0, "bytes_in": 0, "flows": 0,
                                         "failed": 0, "failed_by": {}})  # fmt: skip
        for r in failed:
            a["failed"] += r["flows"]
            a["failed_by"][r["class"]] = a["failed_by"].get(r["class"], 0) + r["flows"]
    top = sorted(remote.values(), key=lambda x: -x["bytes"])[:50]
    for x in top:
        x["local"] = sorted(x["local"])[:5]
    failed_rows = sorted((dict(r, account=who.account(row["id"])) for row in rows for v in row["_by_class"].values()
                          for r in v if r["where"] == "onprem"), key=lambda r: -r["flows"])[:50]  # fmt: skip
    return {"accounts": sorted(accts.values(), key=lambda a: -(a["bytes_in"] + a["bytes_out"] + a["failed"])),
            "top": top, "failed": failed_rows,
            "bytes": sum(a["bytes_in"] + a["bytes_out"] for a in accts.values()),
            "failed_count": sum(a["failed"] for a in accts.values())}  # fmt: skip


def _inside_sources(row: dict, who: _Who) -> list[dict]:
    """Addresses inside the estate that failed on many ports in this account, for the sources table."""
    out = []
    for ip, x in row["_inside"].items():
        if len(x["ports"]) < SWEEP:
            continue
        place = who.address(_ip(ip))
        ports = sorted(x["ports"], key=lambda p: int(p) if p.isdigit() else 0)
        out.append({"ip": ip, "internal": True, "where": place["where"],
                    "source_account": place.get("account"), "source_name": place.get("name", ""),
                    "accounts": [{**who.account(row["id"]), "flows": x["flows"]}], "attempts": x["flows"],
                    "bytes": x["bytes"], "ports": [port_name(p) for p in ports[:12]], "port_count": len(ports),
                    "targets": len(x["targets"]), "target_list": sorted(x["targets"])[:12],
                    "recon": len(ports) >= INTERNAL_SWEEP, "new": x["src_new"], "let_in": []})  # fmt: skip
    return out


# NAT gateways' failures are reasons already, from the failure metrics.
LINK_NAME = {"tgw": "Transit gateway", "dx": "Direct Connect", "vpn": "VPN",
             "pl_services": "PrivateLink service", "pl_endpoints": "PrivateLink endpoint"}  # fmt: skip


def _link_reasons(aid: str, links: dict) -> list[dict]:
    """The links this account owns that failed: a reason to look, with the link's own details."""
    out = []
    for kind, label in LINK_NAME.items():
        for x in links.get(kind) or []:
            bad = [f["text"] for f in x["flags"] if f["kind"] == "health"]
            if x["account"]["id"] != aid or not bad:
                continue
            name = x.get("name") or x["id"]
            ident = f" ({x['id']})" if name != x["id"] else ""
            out.append(
                {"kind": "health", "link": kind, "link_id": x["id"], "text": f"{label} {name}{ident}: {'; '.join(bad)}"}
            )
    return out
