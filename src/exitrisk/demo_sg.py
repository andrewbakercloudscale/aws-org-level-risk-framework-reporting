"""A made-up Security Group Review read for a demo scan's account: no AWS calls.

Builds the same cache document a live read does (security groups, interfaces, network ACL, VPN routes,
flow log, rule history and flow-log slices), so the report, charts and downloads run on the real code path.
The story it tells: a database group open to a whole /12 nobody uses, a DR source seen on one day, a batch
rule added three weeks ago, a public load balancer used through CloudFront, a partner whose new address is
being refused, scanners, and a data centre host turned away by a network ACL.
"""

from __future__ import annotations

import ipaddress
import random

from . import sg_review
from .sg_review import DAY, HOUR

DEMO_BYTES_PER_HOUR = 150_000_000  # what the made-up flow logs "scan" per hour, for the cost estimate


def _host(cidr: str, offset: int) -> str:
    return str(ipaddress.IPv4Network(cidr, strict=False).network_address + offset)


def _vpc_cidr(scan: dict, account: str) -> tuple[str, str]:
    f = sg_review.account_facts(scan, account)
    for region, x in sorted((f.get("access_assets") or {}).items()):
        for v in x.get("vpcs") or []:
            for c in v.get("cidrs") or []:
                if ":" not in c:
                    return region, c
    return (sg_review.regions_of(scan, account) or ["eu-west-1"])[0], "10.20.0.0/16"


def _other_cidr(scan: dict, account: str) -> tuple[str, str] | None:
    for a in scan.get("accounts") or []:
        if a.get("id") == account:
            continue
        for x in (sg_review.account_facts(scan, a["id"]).get("access_assets") or {}).values():
            for v in x.get("vpcs") or []:
                for c in v.get("cidrs") or []:
                    if ":" not in c:
                        return a.get("name") or a["id"], c
    return None


def snapshot(region: str, vpc: str, now: float) -> dict:
    h = lambda o: _host(vpc, o)  # noqa: E731
    sub = {"app": "subnet-0a11", "db": "subnet-0b22", "pub": "subnet-0c33", "ops": "subnet-0d44"}

    def rule(proto, lo, hi, cidrs, descs=None):
        return {"proto": proto, "from": lo, "to": hi, "cidrs": cidrs, "descs": descs or {}, "pls": [], "refs": [],
                "any6": False}  # fmt: skip

    groups = {
        "sg-0app0000000000001": {"name": "app-servers", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 443, 443, ["10.0.0.0/8"], {"10.0.0.0/8": "internal callers"})]},
        "sg-0db00000000000002": {"name": "payments-db", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 5432, 5432, [vpc, "172.16.0.0/12"])]},
        "sg-0alb0000000000003": {"name": "public-alb", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 443, 443, ["0.0.0.0/0"])]},
        "sg-0sftp000000000004": {"name": "partner-sftp", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 22, 22, ["203.0.113.0/24"], {"203.0.113.0/24": "partner"})]},
        "sg-0bat0000000000005": {"name": "batch-workers", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 8080, 8080, ["10.0.0.0/8"])]},
        "sg-0ops0000000000006": {"name": "ops-ssh", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("6", 22, 22, ["10.200.0.0/16"])]},
        "sg-0old0000000000007": {"name": "unused-sg", "vpc": "vpc-0demo", "tag": "",
                                 "rules": [rule("-1", 0, 65535, ["10.0.0.0/8"])]},
    }  # fmt: skip

    def eni(ip, groups_, subnet, kind="EC2 instance", desc="", public=""):
        return {"ips": [ip], "prefixes": [], "groups": groups_, "subnet": subnet, "vpc": "vpc-0demo", "kind": kind,
                "desc": desc, "instance": "", "public": public}  # fmt: skip

    enis = {
        "eni-0app1": eni(h(2 * 256 + 11), ["sg-0app0000000000001"], sub["app"]),
        "eni-0app2": eni(h(2 * 256 + 12), ["sg-0app0000000000001"], sub["app"]),
        "eni-0app3": eni(h(2 * 256 + 13), ["sg-0app0000000000001", "sg-0ops0000000000006"], sub["app"]),
        "eni-0db01": eni(h(4 * 256 + 20), ["sg-0db00000000000002"], sub["db"], "RDS database", "RDSNetworkInterface"),
        "eni-0alb1": eni(h(1 * 256 + 30), ["sg-0alb0000000000003"], sub["pub"], "Load balancer", "ELB app/public"),
        "eni-0sftp": eni(h(1 * 256 + 40), ["sg-0sftp000000000004"], sub["pub"], public="198.51.100.7"),
        "eni-0bat1": eni(h(6 * 256 + 50), ["sg-0bat0000000000005"], sub["app"]),
        "eni-0nat1": eni(h(1 * 256 + 5), [], sub["pub"], "NAT gateway", "Interface for NAT Gateway"),
    }
    nacl = {"id": "acl-0demo", "entries": [
        {"n": 90, "proto": "6", "allow": False, "cidr": "10.200.9.0/24", "from": 22, "to": 22},
        {"n": 100, "proto": "-1", "allow": True, "cidr": "0.0.0.0/0", "from": 0, "to": 65535},
    ]}  # fmt: skip
    return {
        "errors": [],
        "vpcs": [{"id": "vpc-0demo", "name": "main", "cidrs": [vpc]}],
        "groups": groups,
        "enis": enis,
        "prefix_lists": {},
        "nacls": {s: nacl for s in sub.values()},
        "vpns": [{"name": "Johannesburg DC", "routes": ["10.200.0.0/16"]}],
        "flow_logs": [
            {
                "id": "fl-0demo",
                "resource": "vpc-0demo",
                "traffic": "ALL",
                "dest": "cloud-watch-logs",
                "group": "/vpc/flow-logs",
                "format": sg_review.sg_flows.DEFAULT_FORMAT,
                "status": "ACTIVE",
                "created": now - 400 * DAY,
            }
        ],  # fmt: skip
    }


def history(now: float) -> dict:
    return {
        "read": True,
        "whole_since": now - 90 * DAY,
        "events": [
            {"t": now - 40 * DAY, "name": "RevokeSecurityGroupIngress", "who": "network-team", "group":
             "sg-0db00000000000002", "added": [], "removed": [["6", 5432, 5432, "192.168.0.0/16"]], "unknown": False},
            {"t": now - 30 * DAY, "name": "AuthorizeSecurityGroupIngress", "who": "network-team", "group":
             "sg-0ops0000000000006", "added": [["6", 22, 22, "10.200.0.0/16"]], "removed": [], "unknown": False},
            {"t": now - 30 * DAY + 60, "name": "RevokeSecurityGroupIngress", "who": "network-team", "group":
             "sg-0ops0000000000006", "added": [], "removed": [["6", 22, 22, "10.0.0.0/8"]], "unknown": False},
            {"t": now - 20 * DAY, "name": "AuthorizeSecurityGroupIngress", "who": "batch-pipeline", "group":
             "sg-0bat0000000000005", "added": [["6", 8080, 8080, "10.0.0.0/8"]], "removed": [], "unknown": False},
        ],
    }  # fmt: skip


def _patterns(vpc: str, other: tuple | None) -> list[dict]:
    """Who talks to whom: (source, target interface and address, port, accepted?, when active)."""
    h = lambda o: _host(vpc, o)  # noqa: E731
    o = (lambda n: _host(other[1], n)) if other else (lambda n: _host("10.99.0.0/16", n))
    app = [("eni-0app1", h(2 * 256 + 11)), ("eni-0app2", h(2 * 256 + 12)), ("eni-0app3", h(2 * 256 + 13))]
    db = ("eni-0db01", h(4 * 256 + 20))
    alb = ("eni-0alb1", h(256 + 30))
    sftp = ("eni-0sftp", h(256 + 40))
    bat = ("eni-0bat1", h(6 * 256 + 50))
    pats = []
    # internal callers of the app servers: this VPC's load balancer and another account
    for i in range(6):
        pats.append({"src": h(256 + 100 + i), "to": app[i % 3], "port": 443, "ok": True, "p": 1.0, "rate": 60})
    for i in range(4):
        pats.append({"src": o(3 * 256 + 10 + i), "to": app[i % 3], "port": 443, "ok": True, "p": 0.9, "rate": 20})
    # the data centre, over the VPN
    for i in range(3):
        pats.append({"src": _host("10.200.4.0/24", 21 + i), "to": app[0], "port": 443, "ok": True, "p": 0.7, "rate": 8})
    pats.append({"src": "10.200.4.21", "to": app[2], "port": 22, "ok": True, "p": 0.3, "rate": 2})
    # app servers to the database
    for ip in app:
        pats.append({"src": ip[1], "to": db, "port": 5432, "ok": True, "p": 1.0, "rate": 200})
    # the DR replica in this VPC: seen on one day, 45 days ago, then on a failover test 9 days ago
    pats.append({"src": h(9 * 256 + 5), "to": db, "port": 5432, "ok": True, "only": [45, 9], "rate": 900})
    # monthly reconciliation from the data centre: the first of each month
    pats.append({"src": "10.200.7.15", "to": app[1], "port": 443, "ok": True, "monthly": True, "rate": 300})
    # batch workers, since the rule was added 20 days ago
    for i in range(3):
        pats.append({"src": h(5 * 256 + 60 + i), "to": bat, "port": 8080, "ok": True, "p": 0.8, "rate": 30,
                     "after": 19})  # fmt: skip
    # the public load balancer: CloudFront and the internet
    for i in range(8):
        pats.append({"src": _host("130.176.0.0/16", 7 * 256 + i), "to": alb, "port": 443, "ok": True, "p": 1.0,
                     "rate": 500})  # fmt: skip
    for i in range(5):
        pats.append({"src": _host("41.0.0.0/11", 1000 + 97 * i), "to": alb, "port": 443, "ok": True, "p": 0.4,
                     "rate": 5})  # fmt: skip
    # the partner: two addresses used, and their new one (a Zscaler egress) refused for the last 6 days
    pats.append({"src": "203.0.113.10", "to": sftp, "port": 22, "ok": True, "p": 0.6, "rate": 6, "before": 6})
    pats.append({"src": "203.0.113.11", "to": sftp, "port": 22, "ok": True, "p": 0.2, "rate": 3})
    pats.append({"src": "165.225.12.40", "to": sftp, "port": 22, "ok": False, "p": 0.6, "rate": 6, "after": 6})
    # refused inside: a new service in another account trying the database, and a data centre host the ACL turns away
    pats.append({"src": o(4 * 256 + 44), "to": db, "port": 5432, "ok": False, "p": 0.9, "rate": 40, "after": 3})
    pats.append({"src": "10.200.9.9", "to": app[0], "port": 22, "ok": False, "p": 0.5, "rate": 4})
    # refused from the internet: health checks to a closed port, webhooks, scanners
    for i in range(3):
        pats.append({"src": _host("54.228.16.0/26", 8 + i), "to": alb, "port": 80, "ok": False, "p": 1.0,
                     "rate": 30})  # fmt: skip
    pats.append({"src": "140.82.112.5", "to": sftp, "port": 8443, "ok": False, "p": 0.3, "rate": 3})
    for i in range(12):
        pats.append({"src": _host("162.142.125.0/24", 10 + 17 * i), "to": sftp, "port": 3389, "ok": False,
                     "p": 0.25, "rate": 2, "sweep": True})  # fmt: skip
    pats.append({"src": "185.220.101.33", "to": alb, "port": 3389, "ok": False, "p": 0.2, "rate": 1, "sweep": True})
    return pats


def _active(p: dict, s: float, e: float, now: float, rnd: random.Random) -> bool:
    age_s, age_e = (now - e) / DAY, (now - s) / DAY
    if "only" in p:
        return any(age_s <= d < age_e or (age_e - age_s < 1 and int(age_s) == d) for d in p["only"])
    if p.get("monthly"):
        import datetime as dt

        t = s
        while t < e:
            if dt.datetime.fromtimestamp(t, dt.timezone.utc).day == 1:
                return True
            t += HOUR
        return False
    if "after" in p and age_e > p["after"] + (e - s) / DAY:
        return False
    if "before" in p and age_s < p["before"]:
        return False
    span = (e - s) / HOUR
    return rnd.random() < 1 - (1 - p["p"]) ** max(1.0, span / 6)


def chunk(region: str, s: int, e: int, pats: list, now: float, rnd: random.Random) -> dict:
    rows, pub = [], []
    hours = (e - s) / HOUR
    for p in pats:
        if not _active(p, s, e, now, rnd):
            continue
        eni, dst = p["to"]
        flows = max(1, int(p["rate"] * hours * rnd.uniform(0.6, 1.4)))
        private = ipaddress.IPv4Address(p["src"]).is_private
        if p["ok"] or private:
            rows.append([p["src"], dst, eni, "6", p["port"], "ACCEPT" if p["ok"] else "REJECT", flows])
        else:
            ports = rnd.randint(12, 40) if p.get("sweep") else 1
            pub.append([p["src"], flows * ports, ports, 3 if p.get("sweep") else 1, dst, eni, p["port"], "6"])
    # replies to the account's own connections land on high ports: kept out of the report
    eni, dst = pats[0]["to"]
    rows.append(["52.95.110.1", dst, eni, "6", 32768, "ACCEPT", max(1, int(50 * hours))])
    return {"r": region, "s": s, "e": e, "st": "ok", "b": int(DEMO_BYTES_PER_HOUR * hours), "rows": rows, "pub": pub,
            "pc": False, "err": ""}  # fmt: skip


def build_doc(scan: dict, account: str, now: float, days: int, existing: dict | None = None) -> dict:
    acct = sg_review.scan_account(scan, account) or {"name": account}
    region, vpc = _vpc_cidr(scan, account)
    doc = (
        existing
        if existing and existing.get("mode") == "demo"
        else sg_review.new_doc(account, acct.get("name", ""), "demo")
    )
    qsets = [{"format": sg_review.sg_flows.DEFAULT_FORMAT, "groups": ["/vpc/flow-logs"]}]
    doc["regions"][region] = {"snapshot": snapshot(region, vpc, now), "history": history(now), "taken": now,
                              "query_sets": qsets}  # fmt: skip
    rnd = random.Random(int(account) if account.isdigit() else 7)  # noqa: S311 - made-up traffic, not security
    pats = _patterns(vpc, _other_cidr(scan, account))
    have = [(c["s"], c["e"]) for c in doc["chunks"] if c["r"] == region]
    todo = sg_review.plan(now, days, have)
    for s, e in todo:
        doc["chunks"].append(chunk(region, s, e, pats, now, rnd))
    nbytes = sum(int(DEMO_BYTES_PER_HOUR * (e - s) / HOUR) for s, e in todo)
    doc["reads"].append({"at": now, "days": days, "bytes": nbytes, "slices": len(todo)})
    return doc
