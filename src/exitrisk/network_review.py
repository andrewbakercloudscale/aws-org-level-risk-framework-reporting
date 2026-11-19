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
import time

from .account_map import FAIL_METRIC_CAT
from .filtering import AccountFilter
from .logging_config import get_logger
from .recon import account_probes
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

# Each kind of failure: key, group, what, kind. Kinds: "security" (worth a look as a possible attack or
# misuse), "health" (something that should have worked did not), "defence" (a control turning traffic away,
# as it should: counted, not a fault), "info" (shown, judged by neither).
CLASSES = [
    ("refused_in_internet", "Flow logs", "Refused coming in from the internet", "defence"),
    ("refused_in_private", "Flow logs", "Refused coming in from other accounts or private networks", "security"),
    ("refused_internal", "Flow logs", "Refused inside the account", "health"),
    ("refused_out", "Flow logs", "Refused going out", "health"),
    ("unanswered", "Flow logs", "Not answered: connection attempts retried with no reply (timeouts)", "health"),
    ("reset", "Flow logs", "Reset before any data (RST): no one listening, or cut", "info"),
    ("trail_denied", "API calls (CloudTrail)", "Calls refused by IAM or a policy", "security"),
    ("trail_login", "API calls (CloudTrail)", "Failed console sign-ins", "security"),
    ("waf_blocked", "WAF", "Requests blocked by web ACL rules", "defence"),
    ("nfw_dropped", "Network Firewall", "Packets dropped by firewall rules", "defence"),
    ("nlb_sg_in", "Network load balancers", "Flows blocked by the security group coming in", "defence"),
    ("nlb_sg_out", "Network load balancers", "Flows blocked by the security group going out", "health"),
    ("nlb_elb_reset", "Network load balancers", "Connections reset by the load balancer", "health"),
    ("nlb_target_reset", "Network load balancers", "Connections reset by targets", "health"),
    ("nlb_tls", "Network load balancers", "TLS handshakes failed", "health"),
    ("alb_elb_4xx", "Application load balancers", "Requests refused by the load balancer (4xx)", "info"),
    ("alb_elb_5xx", "Application load balancers", "Load balancer errors (5xx)", "health"),
    ("alb_target_5xx", "Application load balancers", "Errors returned by targets (5xx)", "health"),
    ("alb_target_conn", "Application load balancers", "Connections to targets failed", "health"),
    ("alb_rejected", "Application load balancers", "Connections rejected at the connection limit", "health"),
    ("alb_tls", "Application load balancers", "TLS handshakes failed", "health"),
    ("api_4xx", "API Gateway", "Requests refused (4xx)", "info"),
    ("api_5xx", "API Gateway", "Errors (5xx)", "health"),
    ("vpcs_rst", "PrivateLink", "Connections reset by this account's endpoint services", "health"),
    ("vpce_dropped", "PrivateLink", "Packets dropped at interface endpoints", "health"),
    ("db_login", "Databases", "Failed database sign-ins (Aurora MySQL)", "security"),
    ("nat_unanswered", "NAT gateways", "Connections out with no response", "health"),
    ("nat_port", "NAT gateways", "Connections failed: no source port free", "health"),
    ("nat_drop", "NAT gateways", "Packets dropped", "health"),
    ("tgw_blackhole", "Transit gateways", "Packets dropped by blackhole routes", "health"),
    ("tgw_noroute", "Transit gateways", "Packets dropped with no route", "health"),
]
KIND_OF = {k: kind for k, _, _, kind in CLASSES}
WHERE = {"internet": "The internet", "account": "Another account",
         "onprem": "Private network outside the scan (on premises)", "own": "Inside the account"}  # fmt: skip
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


def build_network_review(scan: dict, account_filter: AccountFilter | None = None) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    checked = (scan.get("assurance") or {}).get("accounts") or {}
    accounts = {a["id"]: a for a in scan.get("accounts") or []}
    names = {aid: a.get("name", "") for aid, a in accounts.items()}
    base = {"scan_id": scan.get("id"), "classes": [{"key": k, "group": g, "what": w, "kind": kind}
                                                    for k, g, w, kind in CLASSES], "where": WHERE,
            "not_measured": list(NOT_MEASURED)}  # fmt: skip
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
    probes = account_probes({aid: checked[aid] for aid in scanned})
    trail = _trail_counts(scanned)
    rows, new_rows = [], []
    sources: dict[str, dict] = {}
    cov = {"accounts": len(scanned), "flows_read": 0, "tcp_read": 0, "baseline_read": 0, "baseline_full": 0,
           "s3_only": 0, "s3_accounts": 0, "no_flow_logs": 0, "no_flow_log_accounts": 0, "metrics_read": 0,
           "insights_bytes": 0, "trail_read": any((f.get("trail_denials") or {}).get("read")
                                                  for f in scanned.values())}  # fmt: skip
    for aid, f in scanned.items():
        row = _account(aid, f, own[aid], index, names, trail.get(aid), probes.get(aid), sources, new_rows, cov)
        row["name"] = names.get(aid) or aid
        row["owner"] = owner_of(accounts.get(aid) or {})[0]
        gap = (checked[aid].get("checks") or {}).get("flow_logs") or {}
        if gap.get("status") == "fail":
            row["no_flow_logs"] = gap.get("n") or len(gap.get("ev") or [])
            cov["no_flow_logs"] += row["no_flow_logs"]
            cov["no_flow_log_accounts"] += 1
        rows.append(row)
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
                fl.get("baseline", {}).get("days")
                for f in scanned.values()
                for fl in (f.get("access_flows") or {}).values()
                if fl.get("baseline")
            ),
            7,
        ),  # fmt: skip
        "coverage": cov,
        "totals": totals,
        "accounts": rows,
        "look": [{"id": r["id"], "name": r["name"], "owner": r["owner"], "reasons": r["reasons"]} for r in look],
        "new_today": new_rows[:NEW_ROWS],
        "new_count": len(new_rows),
        "sources": _sources(sources, names),
    }


def _trail_counts(scanned: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in scanned.values():
        for r in (f.get("trail_denials") or {}).get("rows") or []:
            x = out.setdefault(r.get("account") or "", {"trail_denied": 0, "trail_login": 0})
            x["trail_login" if r.get("call") == "ConsoleLogin" else "trail_denied"] += r.get("n") or 0
    return out


def _account(aid, f, nets, index, names, trail, probe, sources, new_rows, cov) -> dict:
    counts = {k: 0 for k, *_ in CLASSES}
    read = {"flows": False, "tcp": False, "baseline": False, "metrics": False}
    where = {k: 0 for k in WHERE}
    failed_bytes = new_pairs = new_sources = new_inside = 0
    top: list[dict] = []
    inside_ports: dict[str, set] = {}
    for fl in (f.get("access_flows") or {}).values():
        cov["insights_bytes"] += int(fl.get("insights_bytes") or 0)
        cov["s3_only"] += len(fl.get("s3_only") or [])
        read["flows"] |= bool(fl.get("reject_covered"))
        read["tcp"] |= bool(fl.get("tcp_covered"))
        base = fl.get("baseline") or {}
        read["baseline"] |= bool(base.get("read"))
        if base.get("full"):
            read["baseline_full"] = True
        for kind, items in (("refused", fl.get("rejected") or []), ("tcp", fl.get("failed_tcp") or [])):
            for r in items:
                src, dst = _ip(r.get("src")), _ip(r.get("dst"))
                if not src or not dst:
                    continue
                s_own, d_own = any(src in n for n in nets), any(dst in n for n in nets)
                if s_own and d_own:
                    local, remote, direction, far = src, dst, "internal", "own"
                else:
                    local, remote, direction = (src, dst, "out") if s_own else (dst, src, "in")
                    far = "internet" if remote.is_global else "account" if index.owner(remote) else "onprem"
                if kind == "tcp":
                    cls = r.get("kind") or "unanswered"
                elif direction == "internal":
                    cls = "refused_internal"
                elif direction == "out":
                    cls = "refused_out"
                else:
                    cls = "refused_in_internet" if far == "internet" else "refused_in_private"
                n = int(r.get("flows") or 0)
                counts[cls] += n
                where[far] += n
                failed_bytes += int(r.get("bytes") or 0)
                owner = index.owner(remote) if far == "account" else None
                item = {"local": str(local), "remote": str(remote), "port": port_name(r.get("port")), "dir": direction,
                        "class": cls, "where": far, "remote_account": names.get(owner) or owner or "",
                        "flows": n, "bytes": int(r.get("bytes") or 0), "new": r.get("new"),
                        "src_new": r.get("src_new")}  # fmt: skip
                top.append(item)
                if r.get("new"):
                    new_pairs += 1
                    if r.get("src_new"):
                        new_sources += 1
                    if not (far == "internet" and direction == "in"):
                        new_inside += 1
                    new_rows.append({**item, "account": aid, "account_name": names.get(aid) or aid})
                if not src.is_global and r.get("port"):  # a scan from inside the estate
                    inside_ports.setdefault(str(src), set()).add(str(r["port"]))
                if src.is_global and not dst.is_global:
                    x = sources.setdefault(str(src), {"ip": str(src), "accounts": set(), "attempts": 0, "ports": set(),
                                                      "targets": set(), "new": False})  # fmt: skip
                    x["accounts"].add(aid)
                    x["attempts"] += n
                    x["targets"].add(str(dst))
                    if r.get("port"):
                        x["ports"].add(str(r["port"]))
                    x["new"] |= bool(r.get("src_new"))
    for x in (f.get("access_failures") or {}).values():
        if "metrics" not in x:
            continue
        read["metrics"] = True
        for key, v in x["metrics"].items():
            cat = FAIL_METRIC_CAT.get(key, key)
            if cat in counts:
                counts[cat] += int(v.get("total") or 0)
    for k, v in (trail or {}).items():
        counts[k] += v
    for k in ("flows", "tcp", "baseline", "metrics"):
        cov[{"flows": "flows_read", "tcp": "tcp_read", "baseline": "baseline_read", "metrics": "metrics_read"}[k]] += (
            1 if read[k] else 0
        )
    cov["baseline_full"] += 1 if read.get("baseline_full") else 0
    if any(fl.get("s3_only") for fl in (f.get("access_flows") or {}).values()):
        cov["s3_accounts"] += 1
    health = sum(v for k, v in counts.items() if KIND_OF[k] == "health")
    security = sum(v for k, v in counts.items() if KIND_OF[k] == "security")
    total = sum(v for k, v in counts.items() if KIND_OF[k] != "info")
    sweeps = sorted(((ip, len(p)) for ip, p in inside_ports.items() if len(p) >= INTERNAL_SWEEP), key=lambda x: -x[1])
    reasons = []
    for sign in (probe or {}).get("network", []) + (probe or {}).get("api", []):
        reasons.append({"kind": "recon", "text": sign})
    for ip, n in sweeps[:3]:
        reasons.append({"kind": "recon", "text": f"{ip}, inside the estate, refused or unanswered on {n} ports: "
                                                 "a scan from inside, or a client misconfigured"})  # fmt: skip
    if new_inside:
        reasons.append({"kind": "new", "text": f"{new_inside} source and target pairs failing today that did not fail "
                                               "before, not counting the internet knocking"})  # fmt: skip
    if counts["refused_out"]:
        reasons.append({"kind": "health", "text": f"{counts['refused_out']:,} connections refused going out"})
    if counts["nat_unanswered"]:
        reasons.append({"kind": "health", "text": f"{counts['nat_unanswered']:,} connections out through NAT with no "
                                                  "response"})  # fmt: skip
    if counts["nat_port"]:
        reasons.append({"kind": "health", "text": f"{counts['nat_port']:,} connections out through NAT failed: no "
                                                  "source port free"})  # fmt: skip
    if counts["tgw_blackhole"] + counts["tgw_noroute"]:
        reasons.append({"kind": "health", "text": f"{counts['tgw_blackhole'] + counts['tgw_noroute']:,} packets "
                                                  "dropped by the transit gateway"})  # fmt: skip
    if counts["unanswered"]:
        reasons.append({"kind": "health", "text": f"{counts['unanswered']:,} connection attempts timed out"})
    attention = 1000 * sum(1 for r in reasons if r["kind"] == "recon") + 10 * new_inside + (1 if reasons else 0)
    top.sort(key=lambda r: (-(r["new"] is True), r["class"] in ("refused_in_internet", "reset"), -r["flows"]))
    return {"id": aid, "read": read, "counts": counts, "where": where, "bytes": failed_bytes, "health": health,
            "security": security, "total": total, "new_pairs": new_pairs, "new_sources": new_sources,
            "new_inside": new_inside, "recon": bool(probe) or bool(sweeps), "reasons": reasons,
            "attention": attention, "top": top[:TOP]}  # fmt: skip


def _totals(rows: list[dict]) -> dict:
    classes = []
    for k, group, what, kind in CLASSES:
        hit = [r for r in rows if r["counts"][k]]
        worst = max(hit, key=lambda r: r["counts"][k], default=None)
        classes.append({"key": k, "group": group, "what": what, "kind": kind,
                        "count": sum(r["counts"][k] for r in rows), "accounts": len(hit),
                        "worst": {"id": worst["id"], "name": worst["name"], "count": worst["counts"][k]}
                        if worst else None})  # fmt: skip
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


def _sources(sources: dict, names: dict) -> list[dict]:
    """Internet addresses refused or unanswered in the estate, the widest first: in several accounts, or on
    many ports or addresses, is someone mapping it."""
    out = []
    for x in sorted(sources.values(), key=lambda x: (-len(x["accounts"]), -len(x["ports"]), -x["attempts"]))[:SOURCES]:
        ports = sorted(x["ports"], key=lambda p: int(p) if p.isdigit() else 0)
        sweep = len(x["accounts"]) > 1 or len(ports) >= 5 or len(x["targets"]) >= 5
        out.append({"ip": x["ip"], "accounts": [{"id": a, "name": names.get(a) or a} for a in sorted(x["accounts"])],
                    "attempts": x["attempts"], "ports": [port_name(p) for p in ports[:10]], "port_count": len(ports),
                    "targets": len(x["targets"]), "recon": sweep, "new": x["new"]})  # fmt: skip
    return out
