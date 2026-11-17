"""Account map: one account's ways in and out, and where each one leads.

Built from the facts the Cloud Assurance step keeps (collectors/access.py): the account's VPCs, the
gateways and endpoints that move data across their edge (internet and egress-only gateways, NAT
gateways, transit gateways, VPC peerings, VPN and Direct Connect, AWS service and PrivateLink
endpoints, public load balancers, API Gateway, CloudFront, AWS Transfer, network interfaces with a
public address), and the IAM paths in (role trusts, bucket policies).

Three columns: where the data sits (the account's VPCs, and the account itself for what lives outside
a VPC), the asset that carries it across the edge, and where that asset leads (the internet, AWS
services, on-premises networks, other accounts, outside parties). Each link says its direction: in,
out or both.

Transit gateways are followed through their route tables when the gateway's owner was scanned: the
account reaches what the route table associated with its attachment sends traffic to, and is reached
from every attachment whose table routes to it. Without the tables, every attached account is shown,
marked as assumed.

With flow-log evidence (the scan option), each conversation is put on the link it crossed: the local
address's subnet, that subnet's route table, the longest route matching the far address. Links whose
VPC was covered and that carried nothing say so: a path nobody used in a day is a candidate to close.
"""

from __future__ import annotations

import ipaddress
import time

from .filtering import AccountFilter
from .logging_config import get_logger

log = get_logger("account_map")

ITEMS = 25  # detail lines kept per node or link
FAIL_HOURS = 24
FAIL_TOP = 10  # resources named per kind of failure
SOURCES = 100  # refused addresses and callers listed
DB_PORTS = {"5432": "PostgreSQL", "3306": "MySQL", "1433": "SQL Server", "1521": "Oracle", "27017": "MongoDB",
            "6379": "Redis", "9042": "Cassandra", "5439": "Redshift", "8182": "Neptune", "9200": "OpenSearch",
            "11211": "Memcached", "50000": "Db2"}  # fmt: skip
# Each kind of failed traffic, in the order the report lists them: key, group, what, direction, and the metric
# families that count its resources (None: filled from flow logs or CloudTrail).
FAIL_CATS = [
    ("flow_in", "Flow logs", "Connections refused coming in", "in", None),
    ("flow_internet", "Flow logs", "of which from the internet", "in", None),
    ("flow_out", "Flow logs", "Connections refused going out", "out", None),
    ("trail_denied", "API calls (CloudTrail)", "Calls refused by IAM or a policy", "in", None),
    ("trail_login", "API calls (CloudTrail)", "Failed console sign-ins", "in", None),
    ("waf_blocked", "WAF", "Requests blocked by web ACL rules", "in", ("waf", "waf_cf")),
    ("nfw_dropped", "Network Firewall", "Packets dropped by firewall rules", "both", ("nfw",)),
    ("nlb_sg_in", "Network load balancers", "Flows blocked by the security group coming in", "in", ("nlb",)),
    ("nlb_sg_out", "Network load balancers", "Flows blocked by the security group going out", "out", ("nlb",)),
    ("nlb_elb_reset", "Network load balancers", "Connections reset by the load balancer", "in", ("nlb",)),
    ("nlb_target_reset", "Network load balancers", "Connections reset by targets", "in", ("nlb",)),
    ("nlb_tls", "Network load balancers", "TLS handshakes failed", "in", ("nlb",)),
    ("alb_elb_4xx", "Application load balancers", "Requests refused by the load balancer (4xx)", "in", ("alb",)),
    ("alb_elb_5xx", "Application load balancers", "Load balancer errors (5xx)", "in", ("alb",)),
    ("alb_target_5xx", "Application load balancers", "Errors returned by targets (5xx)", "in", ("alb",)),
    ("alb_rejected", "Application load balancers", "Connections rejected at the connection limit", "in", ("alb",)),
    ("alb_tls", "Application load balancers", "TLS handshakes failed", "in", ("alb",)),
    (
        "api_4xx",
        "API Gateway",
        "Requests refused (4xx: denied, unauthorised, throttled)",
        "in",
        ("api_rest", "api_http"),
    ),
    ("api_5xx", "API Gateway", "Errors (5xx)", "in", ("api_rest", "api_http")),
    ("vpcs_rst", "PrivateLink", "Connections reset by this account's endpoint services", "in", ("vpcs",)),
    ("vpce_dropped", "PrivateLink", "Packets dropped at interface endpoints", "out", ("vpce",)),
    ("flow_db", "Databases", "Connections refused to database ports", "in", None),
    ("db_login", "Databases", "Failed database sign-ins (Aurora MySQL)", "in", ("aurora_mysql",)),
    ("nat_port", "NAT gateways", "Connections failed: no source port free", "out", ("nat",)),
    ("nat_drop", "NAT gateways", "Packets dropped", "out", ("nat",)),
    ("tgw_blackhole", "Transit gateways", "Packets dropped by blackhole routes", "both", ("tgw",)),
    ("tgw_noroute", "Transit gateways", "Packets dropped with no route", "both", ("tgw",)),
]
FAIL_METRIC_CAT = {
    **{f"nlb_sg_{d}_{p}": f"nlb_sg_{d}" for d in ("in", "out") for p in ("tcp", "udp", "icmp")},
    "waf_blocked_cf": "waf_blocked",
    "api_rest_4xx": "api_4xx",
    "api_http_4xx": "api_4xx",
    "api_rest_5xx": "api_5xx",
    "api_http_5xx": "api_5xx",
}


def _count(n) -> str:
    return f"{int(n):,}"


# Each asset kind: label, direction (in, out, both), what it is.
KINDS = {
    "vpc": ("VPC", "both", "A virtual network of the account"),
    "account": ("Account-wide", "both", "What lives outside a VPC: IAM, API Gateway, CloudFront, AWS Transfer"),
    "igw": ("Internet gateway", "both", "Public subnets reach the internet, and the internet reaches public addresses"),
    "eigw": ("Egress-only internet gateway", "out", "IPv6 traffic out to the internet, nothing in"),
    "nat": ("NAT gateway", "out", "Private subnets reach the internet; nothing starts from outside"),
    "tgw": ("Transit gateway", "both", "Routes between VPCs, accounts, VPNs and Direct Connect"),
    "pcx": ("VPC peering", "both", "A direct link between two VPCs"),
    "vgw": ("VPN gateway", "both", "Site-to-site VPN or Direct Connect into the VPC"),
    "vpn": ("Site-to-site VPN", "both", "An encrypted tunnel to a network outside AWS"),
    "dx": ("Direct Connect", "both", "A private line to a network outside AWS"),
    "vpce": ("AWS service endpoints", "out", "Private paths from the VPC to AWS services"),
    "pl-out": ("PrivateLink endpoint", "out", "Connects to another account's endpoint service"),
    "pl-in": ("PrivateLink service", "in", "Other accounts may connect to this account's service"),
    "lb": ("Public load balancer", "in", "Internet-facing: takes connections from any address"),
    "api": ("API Gateway", "in", "An API with a public or private endpoint"),
    "cloudfront": ("CloudFront", "in", "A distribution: the internet in, to the origins named"),
    "transfer": ("AWS Transfer", "in", "An SFTP, FTPS or FTP server"),
    "public-ip": ("Public addresses", "both", "Network interfaces with a public IPv4 address"),
    "sg-open": ("Open security groups", "in", "Security groups in use that admit any address"),
    "sg-range": ("Security group ranges", "in", "Security groups in use that admit addresses outside the account"),
    "lambda": ("Lambda functions", "out", "Functions, and where their traffic can go"),
    "role": ("Role trusts", "in", "Roles that principals outside the account may assume"),
    "bucket": ("S3 buckets", "in", "The account's buckets, and who outside the account each one lets in"),
}  # fmt: skip

DESTS = {
    "internet": ("The internet", "internet", "Any public address"),
    "aws": ("AWS services", "aws", "Reached over AWS's network, not the internet"),
    "net:private": ("Other private networks", "onprem", "Private addresses outside every scanned VPC"),
    "net:public": ("Specific internet addresses", "internet", "Named public address ranges"),
    "anyone": ("Anyone", "anyone", "Any AWS principal, no condition naming who"),
    "org": ("Any account in the organisation", "org-any", "aws:PrincipalOrgID or aws:PrincipalOrgPaths"),
}  # fmt: skip


def _net(c):
    try:
        return ipaddress.ip_network(c, strict=False)
    except (ValueError, TypeError):
        return None


def _ip(a):
    try:
        return ipaddress.ip_address(a)
    except (ValueError, TypeError):
        return None


def parse_ranges(text: str) -> list[tuple]:
    """Named on-premises ranges, one per comma or line: "10.200.0.0/16 Johannesburg DC" (the name is optional)."""
    out = []
    for part in (text or "").replace("\n", ",").split(","):
        words = part.split()
        net = _net(words[0]) if words else None
        if net and net.prefixlen:
            out.append((net, " ".join(words[1:]) or f"On-premises {net}"))
    return out


def _overlaps(a, b) -> bool:
    return a.version == b.version and a.overlaps(b)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class TgwRouting:
    """Every transit gateway attachment seen in the scan, and the route tables of the gateways scanned."""

    def __init__(self, scanned: dict[str, dict]):
        self.atts: dict[str, dict] = {}
        self.members: dict[str, set[str]] = {}
        self.tables: dict[str, list[dict]] = {}
        self.peers: dict[str, dict] = {}
        for aid, facts in scanned.items():
            for region, n in (facts.get("access_network") or {}).items():
                for a in n.get("tgw_attachments") or []:
                    if a.get("id"):
                        self.atts.setdefault(a["id"], {**a, "region": region})
                    if a.get("tgw"):
                        self.members.setdefault(a["tgw"], set()).update(
                            w for w in (a.get("owner"), a.get("tgw_owner")) if w
                        )
            for region, x in (facts.get("access_assets") or {}).items():
                for t in x.get("tgw_tables") or []:
                    self.tables.setdefault(t["tgw"], []).append({**t, "owner": aid, "region": region})
                for p in x.get("tgw_peerings") or []:
                    self.peers[p["id"]] = p

    def read(self, tgw: str) -> bool:
        return tgw in self.tables

    def table_of(self, att: str) -> dict | None:
        tgw = (self.atts.get(att) or {}).get("tgw")
        return next((t for t in self.tables.get(tgw, []) if att in t["associations"]), None)

    def routes_from(self, att: str) -> list[tuple[str, str, bool]]:
        """(destination, target attachment, blackhole) for the table associated with ``att``."""
        t = self.table_of(att)
        if not t:
            return []
        return [(r["dst"], a, r["blackhole"]) for r in t["routes"] for a in r["attachments"] or [None] if a != att]

    def reaches(self, att: str) -> list[tuple[str, str]]:
        """(target attachment, destination) pairs ``att`` can send to: live routes only."""
        return [(a, d) for d, a, bh in self.routes_from(att) if a and not bh]

    def reached_by(self, att: str) -> list[tuple[str, str]]:
        """(source attachment, destination) pairs whose table routes to ``att``."""
        tgw = (self.atts.get(att) or {}).get("tgw")
        out = []
        for t in self.tables.get(tgw, []):
            for r in t["routes"]:
                if att in (r["attachments"] or []) and not r["blackhole"]:
                    out += [(src, r["dst"]) for src in t["associations"] if src != att]
        return out

    def far_end(self, att: str) -> tuple[str, str]:
        """(kind, id) of what an attachment leads to: an account, an on-premises network or a peered gateway."""
        a = self.atts.get(att) or {}
        kind = a.get("type") or ""
        if kind == "vpc":
            return "account", a.get("owner") or ""
        if kind == "peering":
            p = self.peers.get(att) or {}
            return "account", p.get("peer_owner") or a.get("owner") or ""
        if kind in ("vpn", "direct-connect-gateway", "connect"):
            return "onprem", f"{kind} {a.get('resource') or att}"
        return "other", att


def build_account_map(
    scan: dict, account: str | None = None, account_filter: AccountFilter | None = None, onprem: str = ""
) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    checked = (scan.get("assurance") or {}).get("accounts") or {}
    org_accounts = scan.get("org_accounts") or {}
    names = {a["id"]: a.get("name", "") for a in scan.get("accounts") or []}
    names.update({k: v.get("name", "") for k, v in org_accounts.items() if k not in names})
    scanned = {
        aid: res.get("facts") or {} for aid, res in checked.items() if account_filter.matches(names.get(aid, aid))
    }
    with_assets = sorted((a for a, f in scanned.items() if "access_assets" in f), key=lambda a: names.get(a) or a)
    base = {
        "scan_id": scan.get("id"),
        "kinds": {k: {"label": v[0], "dir": v[1], "what": v[2]} for k, v in KINDS.items()},
        "accounts": [{"id": a, "name": names.get(a) or a} for a in with_assets],
    }
    if not with_assets:
        reason = (
            "This scan has no Cloud Assurance checks: run a new scan with Cloud Assurance ticked."
            if not checked
            else "This scan was made before the account map existed. Run a new scan with Cloud Assurance ticked."
        )
        return {**base, "available": False, "reason": reason}
    me = account if account in with_assets else with_assets[0]
    facts = scanned[me]
    m = _Map(me, names, scanned, org_accounts, parse_ranges(onprem))
    m.build(facts)
    flows = m.flows(facts)
    failures = m.failures(facts, flows)
    log.info("account map %s: %d nodes, %d links in %.2fs", me, len(m.nodes), len(m.links),
             time.perf_counter() - started)  # fmt: skip
    return {
        **base,
        "available": True,
        "account": {"id": me, "name": names.get(me) or me},
        "regions": sorted(set(facts.get("access_assets") or {})),
        "nodes": list(m.nodes.values()),
        "links": sorted(m.links.values(), key=lambda x: (x["from"], x["to"])),
        "flows": flows,
        "failures": failures,
        "buckets": m.buckets,
        "lambdas": m.lambdas if any("lambdas" in x for x in (facts.get("access_assets") or {}).values()) else None,
        "ranges": m.range_rows(),
        "notes": m.notes,
    }


class _Map:
    def __init__(self, me: str, names: dict, scanned: dict, org_accounts: dict, named: list[tuple] | None = None):
        self.me, self.names, self.scanned, self.org = me, names, scanned, org_accounts
        self.named = named or []
        self.buckets: list[dict] = []
        self.ranges: dict[str, dict] = {}  # outside range -> how it is reached
        self.route_dest: dict[tuple, str] = {}  # (route table, destination) -> the node it leads to
        self.lambdas: list[dict] = []
        self.nodes: dict[str, dict] = {}
        self.links: dict[tuple, dict] = {}
        self.notes: list[str] = []
        self.tgw = TgwRouting(scanned)
        self.cidr_owner: list[tuple] = []
        for aid, f in scanned.items():
            if aid == me:
                continue
            for regions in (f.get("access_network") or {}, f.get("access_assets") or {}):
                for n in regions.values():
                    for c in n.get("cidrs") or [c for v in n.get("vpcs") or [] for c in v.get("cidrs") or []]:
                        net = _net(c)
                        if net:
                            self.cidr_owner.append((net, aid))
        self.attach: dict[str, set[str]] = {}  # asset -> VPC nodes it serves
        f = scanned.get(me) or {}
        self.own_nets = [n for x in (f.get("access_assets") or {}).values() for v in x.get("vpcs") or []
                         for n in map(_net, v.get("cidrs") or []) if n]  # fmt: skip

    # ------------------------------------------------------------------ nodes and links

    def node(self, nid: str, col: str, kind: str, label: str, sub: str = "", region: str = "", **kw) -> str:
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "col": col, "kind": kind, "label": label, "sub": sub, "region": region,
                                   "items": [], "count": 0, "flags": [], **kw}  # fmt: skip
        return nid

    def item(self, nid: str, text: str) -> None:
        n = self.nodes[nid]
        if text not in n["items"]:
            n["count"] += 1
            if len(n["items"]) < ITEMS:
                n["items"].append(text)

    def flag(self, nid: str, text: str) -> None:
        if text not in self.nodes[nid]["flags"]:
            self.nodes[nid]["flags"].append(text)

    def link(self, src: str, dst: str, direction: str, detail: str = "", assumed: bool = False) -> dict:
        key = (src, dst)
        x = self.links.get(key)
        if x is None:
            x = self.links[key] = {"from": src, "to": dst, "dir": direction, "details": [], "bytes_in": 0,
                                   "bytes_out": 0, "flows": 0, "observed": None, "assumed": assumed,
                                   "top": [], "rejected": 0}  # fmt: skip
        elif x["dir"] != direction:
            x["dir"] = "both"
        if not assumed:
            x["assumed"] = False
        if detail and detail not in x["details"] and len(x["details"]) < ITEMS:
            x["details"].append(detail)
        return x

    def dest(self, key: str) -> str:
        label, kind, sub = DESTS[key]
        return self.node(key, "dest", kind, label, sub)

    def account(self, aid: str) -> str:
        if aid == self.me:
            return self.node(f"self:{aid}", "dest", "self", "This account (another VPC)", aid)
        if aid in self.scanned:
            sub, kind = aid, "account"
        elif aid in self.org or aid in self.names:
            sub, kind = f"{aid} · in the organisation, not in this report", "org"
        else:
            sub, kind = f"{aid} · outside the organisation", "external"
        return self.node(aid, "dest", kind, self.names.get(aid) or aid, sub, pivot=aid in self.scanned)

    def onprem(self, key: str, label: str, sub: str = "") -> str:
        return self.node(f"onprem:{key}", "dest", "onprem", label, sub)

    def asset(self, nid: str, kind: str, label: str, region: str, sub: str = "") -> str:
        return self.node(nid, "asset", kind, label, sub or KINDS[kind][2], region, dir=KINDS[kind][1])

    def serve(self, asset: str, vpc_node: str) -> None:
        self.attach.setdefault(asset, set()).add(vpc_node)

    def principal(self, p: dict) -> str | None:
        kind = p.get("kind")
        if kind == "account":
            return self.account(p["id"])
        if kind in ("anyone", "org"):
            return self.dest(kind)
        if kind == "federated":
            pid = p["id"]
            short = pid.split(":oidc-provider/")[-1].split(":saml-provider/")[-1]
            return self.node(f"fed:{pid}", "dest", "federated", short, "SAML or OIDC identity provider")
        return None

    # ------------------------------------------------------------------ outside address ranges

    def named_range(self, net) -> str | None:
        """The node of the on-premises range you named that ``net`` falls in or covers."""
        hit = next(((n, label) for n, label in self.named if _overlaps(n, net)), None)
        if not hit:
            return None
        n, label = hit
        return self.onprem(f"range:{n}", label, f"on-premises range you named: {n}")

    def outside(self, net, via_onprem: str | None = None) -> str | None:
        """Where an address range outside the account leads: a range you named, the on-premises network
        a VPN or Direct Connect reaches, one scanned account, other private networks or the internet.
        None for the account's own VPCs."""
        if any(_overlaps(net, o) for o in self.own_nets):
            return None
        named = self.named_range(net)
        if named:
            return named
        if via_onprem:
            return via_onprem
        owners = {o for n, o in self.cidr_owner if _overlaps(net, n)}
        inside = {o for n, o in self.cidr_owner if net.version == n.version and net.subnet_of(n)}
        if len(inside) == 1:
            return self.account(inside.pop())
        if owners:
            return None  # a range over several accounts' VPCs: their own links say who
        return self.dest("net:private" if net.is_private else "net:public")

    def note_range(self, net, node: str, how: str) -> None:
        row = self.ranges.setdefault(str(net), {"cidr": str(net), "to": node, "how": []})
        if how not in row["how"] and len(row["how"]) < ITEMS:
            row["how"].append(how)
        self.item(node, str(net))

    def range_rows(self) -> list[dict]:
        rows = []
        for r in self.ranges.values():
            n = self.nodes.get(r["to"]) or {}
            rows.append({**r, "label": n.get("label", ""), "kind": n.get("kind", ""),
                         "named": r["to"].startswith("onprem:range:")})  # fmt: skip
        return sorted(rows, key=lambda r: (not r["named"], r["kind"] != "onprem", _net(r["cidr"]) or r["cidr"]))

    def _routed(self, region: str, x: dict) -> None:
        """Ranges the account's own route tables send to a gateway: where on-premises and other networks sit,
        read even when the transit gateway's own tables were not."""
        vgw_far = {}
        for lk in self.links.values():
            if self.nodes.get(lk["to"], {}).get("kind") == "onprem" and self.nodes.get(lk["from"], {}).get("kind") in (
                "vgw",
                "dx",
            ):
                vgw_far.setdefault(lk["from"], []).append(lk["to"])
        for v in x.get("dx_vifs") or []:  # Direct Connect on a VPN gateway: the gateway leads to the DX location
            dx = f"onprem:dx:{v.get('location')}"
            if v.get("gateway") in self.nodes and dx in self.nodes and dx not in vgw_far.get(v["gateway"], []):
                vgw_far.setdefault(v["gateway"], []).append(dx)
        for t in x.get("routes") or []:
            for r in t["routes"]:
                net = _net(r["dst"])
                if not net or not net.prefixlen or r["blackhole"]:
                    continue
                asset = {"tgw": f"tgw:{r['target']}"}.get(r["kind"], r["target"])
                if r["kind"] not in ("tgw", "vgw", "cloudwan", "gateway") or asset not in self.nodes:
                    continue
                far = vgw_far.get(asset, [])
                via = far[0] if len(far) == 1 else None
                if not via and r["kind"] == "vgw":
                    via = self.onprem(f"vgw:{asset}", "On-premises network", f"through {asset}")
                node = self.outside(net, via)
                if not node:
                    continue
                self.route_dest[(t["id"], r["dst"])] = node
                label = self.nodes[asset]["label"]
                self.note_range(net, node, f"routed to {label} {r['target']}")
                self.item(asset, f"{net} routed here ({t['id']})")
                self.link(asset, node, "both", f"{net} routed here")
        for v in x.get("vpns") or []:
            for c in v.get("routes") or []:
                net = _net(c)
                if net:
                    peer = v.get("customer_ip")
                    far = self.onprem(peer or v["id"], v.get("name") or f"VPN peer {peer}",
                                      f"customer gateway {peer or 'unknown'}")  # fmt: skip
                    node = self.outside(net, far) or far
                    self.note_range(net, node, f"static route on {v['id']}")

    def _lambdas(self, region: str, x: dict) -> None:
        """Each Lambda function: whether it can reach the internet, which outside networks (data centres over
        Direct Connect or VPN, other private ranges) its subnets route to, and whether a function URL lets
        anyone call it."""
        fns = x.get("lambdas")
        if not fns:
            return
        subnet_rt = {s["id"]: s.get("rt") for s in x.get("subnets") or []}
        tables = {t["id"]: t for t in x.get("routes") or []}
        lid = self.asset(f"lambda:{region}", "lambda", f"{len(fns)} Lambda function{'s' if len(fns) > 1 else ''}",
                         region, "Where each function's traffic can go")  # fmt: skip
        counts = {"internet": 0, "central": 0, "networks": 0, "public_url": 0}
        for f in fns:
            nets: dict[str, dict] = {}
            if not f.get("vpc"):
                internet, via = "yes", "outside a VPC: Lambda's own internet access"
                self.serve(lid, "acct")
            else:
                self._vpcs(lid, f["vpc"])
                internet, via = "no", "no default route to a NAT gateway"
                for rt in {subnet_rt.get(sn) for sn in f.get("subnets") or []} - {None}:
                    t = tables.get(rt) or {"routes": []}
                    for r in t["routes"]:
                        if r["blackhole"]:
                            continue
                        if r["dst"] in ("0.0.0.0/0", "::/0"):
                            if r["kind"] == "nat" and internet != "yes":
                                internet, via = "yes", f"NAT gateway {r['target']}"
                            elif r["kind"] in ("tgw", "cloudwan") and internet == "no":
                                internet, via = "central", f"default route to {r['target']} (central egress)"
                            continue
                        node = self.route_dest.get((rt, r["dst"]))
                        if node:
                            n = nets.setdefault(node, {"label": self.nodes[node]["label"], "id": node, "cidrs": [],
                                                       "via": r["target"]})  # fmt: skip
                            if r["dst"] not in n["cidrs"]:
                                n["cidrs"].append(r["dst"])
            url = f.get("url")
            public_url = url == "NONE"
            if internet == "yes":
                self.link(lid, self.dest("internet"), "out", f"{f['name']}: {via}")
            elif internet == "central":
                self.link(lid, self.dest("internet"), "out", f"{f['name']}: {via}", assumed=True)
            for node, n in nets.items():
                self.link(lid, node, "out", f"{f['name']}: {', '.join(n['cidrs'])}")
            if public_url:
                self.link(lid, self.dest("internet"), "in", f"{f['name']}: function URL with no authentication")
                self.flag(lid, "function URL open to anyone")
            counts["internet"] += internet == "yes"
            counts["central"] += internet == "central"
            counts["networks"] += bool(nets)
            counts["public_url"] += public_url
            reach = [{"yes": "internet", "central": "internet (central egress)"}.get(internet, "")] + [
                n["label"] for n in nets.values()
            ]
            self.item(lid, f"{f['name']} → {', '.join(r for r in reach if r) or 'its own VPC only'}")
            self.lambdas.append({"name": f["name"], "region": region, "runtime": f.get("runtime", ""),
                                 "vpc": f.get("vpc", ""), "internet": internet, "internet_via": via,
                                 "networks": list(nets.values()),
                                 "url": "not read" if url is None else url or ""})  # fmt: skip
        self.nodes[lid]["sub"] = (f"{counts['internet']} to the internet"
                                  + (f", {counts['central']} through central egress" if counts["central"] else "")
                                  + f", {counts['networks']} to outside networks")  # fmt: skip

    def _sg_ranges(self, region: str, n: dict) -> None:
        """Security-group rules that admit a range outside the account, other than any address."""
        rows = [r for r in n.get("sg_cidrs") or [] if r.get("cidr") not in ("0.0.0.0/0", "::/0")]
        if not rows:
            return
        sid = None
        for r in rows:
            net = _net(r["cidr"])
            node = self.outside(net) if net else None
            if not node and net:
                if any(_overlaps(net, o) for o in self.own_nets):
                    continue
                node = self.dest("net:private" if net.is_private else "net:public")  # spans several accounts
            if not node:
                continue
            groups = ", ".join(r.get("groups") or [])
            if not sid:
                sid = self.asset(f"sg-range:{region}", "sg-range", "Security groups admitting outside ranges", region)
                self.serve(sid, "acct")
            self.item(sid, f"{r['cidr']} on {r['ports']} ({groups})")
            self.note_range(net, node, f"admitted on {r['ports']} by {groups}")
            self.link(sid, node, "in", f"{r['cidr']} on {r['ports']}")

    # ------------------------------------------------------------------ buckets

    def _buckets(self, f: dict, acct: str) -> None:
        buckets = f.get("buckets") or []
        if not buckets:
            return
        public = [b for b in buckets if b.get("public")]
        shared = [b for b in buckets if b.get("grants")]
        sub = (
            f"{len(public)} public, {len(shared)} shared outside the account"
            if public or shared
            else "none public or shared outside the account"
        )
        bid = self.asset("iam:buckets", "bucket", f"{len(buckets)} S3 bucket{'s' if len(buckets) > 1 else ''}",
                         "global", sub)  # fmt: skip
        self.serve(bid, acct)
        if public:
            self.flag(bid, f"{len(public)} public")
        for b in sorted(buckets, key=lambda b: (not b.get("public"), not b.get("grants"), b["name"])):
            who = []
            if b.get("public"):
                self.link(bid, self.dest("internet"), "in", f"bucket {b['name']} is public")
                who.append({"label": "Anyone on the internet", "kind": "internet", "actions": []})
            for g in b.get("grants") or []:
                src = self.principal(g)
                if not src:
                    continue
                acts = ", ".join(g.get("actions") or [])
                self.link(bid, src, "in", f"bucket {b['name']}" + (f": {acts}" if acts else ""))
                who.append({"label": self.nodes[src]["label"], "kind": self.nodes[src]["kind"], "id": src,
                            "actions": g.get("actions") or [], "conditions": g.get("conditions") or []})  # fmt: skip
            access = ("public" if b.get("public") else "outside" if who else
                      "unknown" if b.get("public") is None and b.get("has_policy") is None else "account")  # fmt: skip
            text = {"public": "public", "outside": f"shared with {', '.join(w['label'] for w in who)}",
                    "account": "this account only", "unknown": "access not read"}[access]  # fmt: skip
            limits = b.get("limits") or {}
            if limits:
                text += "; only from " + ", ".join(v for vs in limits.values() for v in vs)
            self.item(bid, f"{b['name']} ({b.get('region', '')}): {text}")
            self.buckets.append({
                "name": b["name"], "region": b.get("region", ""), "access": access, "who": who, "limits": limits,
                "has_policy": b.get("has_policy"), "tls_only": b.get("tls_only"), "kms": b.get("kms"),
                "acls": b.get("acls"), "versioning": b.get("versioning"), "lock": b.get("lock"),
                "replicated": b.get("replicated"), "classified": bool(b.get("tags")),
            })  # fmt: skip
        if not any("has_policy" in b for b in buckets):
            self.notes.append("Bucket network limits (VPC endpoint, VPC and address conditions) need a new scan.")

    # ------------------------------------------------------------------ the map

    def build(self, f: dict) -> None:
        me = self.me
        acct = self.node("acct", "vpc", "account", "Account-wide", "IAM, API Gateway, CloudFront, AWS Transfer")
        assets = f.get("access_assets") or {}
        network = f.get("access_network") or {}
        self.vpc_node: dict[str, str] = {}
        for region, x in assets.items():
            for v in x.get("vpcs") or []:
                nid = self.node(f"vpc:{v['id']}", "vpc", "vpc", v.get("name") or v["id"],
                                f"{v['id']} · {', '.join(v.get('cidrs') or [])}", region,
                                default=v.get("default", False))  # fmt: skip
                self.vpc_node[v["id"]] = nid
                if v.get("default"):
                    self.flag(nid, "default VPC")
            # where each route table sends traffic out of the VPC: links VPCs to gateways
            self.route_vpcs: dict[str, set[str]] = {}
            for t in x.get("routes") or []:
                for r in t["routes"]:
                    self.route_vpcs.setdefault(r["target"], set()).add(t["vpc"])
            self._gateways(region, x, network.get(region) or {})
            if x.get("refused"):
                self.notes.append(f"{region}: not read: {', '.join(x['refused'])}")
            if x.get("cut"):
                self.notes.append(f"{region}: lists cut at their limit: {', '.join(x['cut'])}")
        for region, x in assets.items():
            self._routed(region, x)
            self._lambdas(region, x)
        for region, n in network.items():
            self._sg_ranges(region, n)
            self._privatelink(region, n)
            open_any = [r for r in n.get("sg_cidrs") or [] if r.get("cidr") == "0.0.0.0/0"]
            if open_any:
                sid = self.asset(f"sg-open:{region}", "sg-open", "Security groups open to any address", region)
                for r in open_any:
                    self.item(sid, f"{', '.join(r.get('groups') or [])} on {r['ports']}")
                self.serve(sid, acct)
                self.link(sid, self.dest("internet"), "in", f"{len(open_any)} rule(s) admit 0.0.0.0/0")
        for d in f.get("cloudfront") or []:
            cid = self.asset("cloudfront", "cloudfront", "CloudFront distributions", "global")
            self.item(cid, f"{d['id']} {d.get('domain', '')} → {', '.join(d.get('origins') or []) or 'no origin'}")
            if not d.get("waf"):
                self.flag(cid, "without a web firewall")
            self.serve(cid, acct)
            self.link(cid, self.dest("internet"), "in", d.get("domain", ""))
        # IAM
        trusts = f.get("access_trusts") or []
        if trusts:
            rid = self.asset("iam:roles", "role", "Roles trusted from outside", "global")
            self.serve(rid, acct)
            for t in trusts:
                src = self.principal(t)
                if src:
                    extra = " (external id)" if t.get("external_id") else ""
                    self.item(rid, f"{t['role']} ← {self.nodes[src]['label']}{extra}")
                    self.link(rid, src, "in", f"role {t['role']}{extra}")
        self._buckets(f, acct)
        for asset, vpcs in self.attach.items():
            d = self.nodes[asset].get("dir", "both")
            for v in sorted(vpcs):
                self.link(v, asset, d)
        if not any(n["col"] == "asset" for n in self.nodes.values()):
            self.notes.append("No way in or out was found: no gateway, endpoint, public address or outside trust.")
        if me not in self.scanned:
            self.notes.append("The account was not read.")

    def _vpcs(self, asset: str, *vpc_ids) -> None:
        for v in vpc_ids:
            if v and v in self.vpc_node:
                self.serve(asset, self.vpc_node[v])

    def _gateways(self, region: str, x: dict, n: dict) -> None:
        internet = self.dest("internet")
        for g in x.get("igws") or []:
            aid = self.asset(g["id"], "igw", "Internet gateway", region, g["id"])
            self._vpcs(aid, g.get("vpc"))
            routed = self.route_vpcs.get(g["id"], set())
            if not routed:
                self.flag(aid, "no route table sends traffic to it")
            self.link(aid, internet, "both", g["id"])
        for g in x.get("eigws") or []:
            aid = self.asset(g["id"], "eigw", "Egress-only gateway", region, g["id"])
            self._vpcs(aid, g.get("vpc"))
            self.link(aid, internet, "out", g["id"])
        for g in x.get("nats") or []:
            public = g.get("type", "public") == "public"
            aid = self.asset(g["id"], "nat", "NAT gateway" if public else "Private NAT gateway", region,
                             f"{g['id']} · {g.get('public_ip') or 'private'}")  # fmt: skip
            self._vpcs(aid, g.get("vpc"))
            self.link(aid, internet if public else self.dest("net:private"), "out", g.get("public_ip") or g["id"])
        vgw_vpcs = {g["id"]: g.get("vpcs") or [] for g in x.get("vgws") or []}
        for g in x.get("vgws") or []:
            aid = self.asset(g["id"], "vgw", "VPN gateway", region, g["id"])
            self._vpcs(aid, *g.get("vpcs") or [])
        for v in x.get("vpns") or []:
            gw = v.get("gateway") or ""
            far = self.onprem(v.get("customer_ip") or v["id"], v.get("name") or f"VPN peer {v.get('customer_ip')}",
                              f"customer gateway {v.get('customer_ip') or 'unknown'}")  # fmt: skip
            tunnels = f"{v.get('up', 0)} of {v.get('tunnels', 0)} tunnels up"
            if gw.startswith("vgw-"):
                aid = self.asset(gw, "vgw", "VPN gateway", region, gw)
                self._vpcs(aid, *vgw_vpcs.get(gw, []))
                self.link(aid, far, "both", f"{v['id']}: {tunnels}")
                self.item(aid, f"{v['id']} → {v.get('customer_ip')}: {tunnels}")
            # VPNs on a transit gateway are followed through the gateway below
        for v in x.get("dx_vifs") or []:
            aid = self.asset(f"dx:{v['id']}", "dx", "Direct Connect", region, f"{v['id']} · {v.get('type')}")
            gw = v.get("gateway") or ""
            self._vpcs(aid, *vgw_vpcs.get(gw, []))
            if not self.attach.get(aid):
                self.serve(aid, "acct")
            far = self.onprem(f"dx:{v.get('location')}", f"Direct Connect {v.get('location') or ''}".strip(),
                              "on-premises over a private line")  # fmt: skip
            self.link(aid, far, "both", f"{v.get('name') or v['id']} ({v.get('type')}) via {gw or 'no gateway'}")
        by_vpc: dict[str, list[dict]] = {}
        for e in x.get("aws_endpoints") or []:
            by_vpc.setdefault(e.get("vpc") or "", []).append(e)
        for vpc, eps in by_vpc.items():
            aid = self.asset(f"vpce:{vpc}", "vpce", f"{len(eps)} AWS service endpoint{'s' if len(eps) > 1 else ''}",
                             region, vpc)  # fmt: skip
            self._vpcs(aid, vpc)
            for e in eps:
                self.item(aid, f"{e['service']} ({e.get('type', '').lower()})" +
                          (": policy allows everything" if e.get("open_policy") else ""))  # fmt: skip
            self.link(aid, self.dest("aws"), "out", ", ".join(sorted({e["service"] for e in eps}))[:200])
        pub: dict[tuple, list[dict]] = {}
        for p in x.get("public_ips") or []:
            if p.get("what") in ("NAT gateway", "load balancer"):
                continue  # shown as their own assets
            pub.setdefault((p.get("vpc") or "", p.get("what") or ""), []).append(p)
        for (vpc, what), items in pub.items():
            aid = self.asset(f"pub:{vpc}:{what}", "public-ip", f"{len(items)} {what}{'s' if len(items) > 1 else ''} "
                             "with a public IP", region, vpc)  # fmt: skip
            self._vpcs(aid, vpc)
            for p in items:
                self.item(aid, f"{p['id']} {p['ip']} ({', '.join(p.get('groups') or [])})")
            self.link(aid, internet, "both", f"{len(items)} public address(es)")
        for lb in x.get("lbs") or []:
            aid = self.asset(f"lb:{region}:{lb['name']}", "lb", lb["name"], region,
                             f"{lb.get('type')} load balancer · {lb.get('dns')}")  # fmt: skip
            self._vpcs(aid, lb.get("vpc"))
            self.link(aid, internet, "in", lb.get("dns") or "")
        for a in x.get("apis") or []:
            private = a.get("endpoint") == "PRIVATE"
            aid = self.asset(f"api:{region}", "api", "API Gateway", region, "REST, HTTP and WebSocket APIs")
            self.serve(aid, "acct")
            self.item(aid, f"{a['name']} ({a['kind']}, {a['endpoint'].lower()})")
            if private:
                self.link(aid, self.dest("net:private"), "in", f"{a['name']} through interface endpoints")
            else:
                self.link(aid, internet, "in", a["name"])
        for s in x.get("transfer") or []:
            aid = self.asset(f"transfer:{region}", "transfer", "AWS Transfer", region, "SFTP / FTPS / FTP servers")
            self.serve(aid, "acct")
            self.item(aid, f"{s['id']} ({s['endpoint'].lower()})")
            self.link(aid, internet if s["endpoint"] == "PUBLIC" else self.dest("net:private"), "in", s["id"])
        # peering
        for p in n.get("peerings") or []:
            other = p["accepter"] if p.get("requester") == self.me else p.get("requester")
            aid = self.asset(p["id"], "pcx", "VPC peering", region, p["id"])
            self._vpcs(aid, *self.route_vpcs.get(p["id"], set()))
            if not self.attach.get(aid):
                self.flag(aid, "no route table sends traffic to it")
                self.serve(aid, "acct")
            far_cidrs = p["accepter_cidrs"] if p.get("requester") == self.me else p.get("requester_cidrs")
            self.link(aid, self.account(other) if other else self.dest("net:private"), "both",
                      f"{p['id']} to {', '.join(far_cidrs or []) or 'their VPC'}")  # fmt: skip
        # transit gateways
        mine = [a for a in n.get("tgw_attachments") or [] if a.get("owner") == self.me and a.get("tgw")]
        for att in mine:
            self._tgw(region, att, x)

    def _tgw(self, region: str, att: dict, x: dict) -> None:
        tgw = att["tgw"]
        owner = att.get("tgw_owner") or ""
        aid = self.asset(f"tgw:{tgw}", "tgw", "Transit gateway", region,
                         f"{tgw} · owned by {self.names.get(owner) or owner or 'unknown'}")  # fmt: skip
        self._vpcs(aid, att.get("resource"), *self.route_vpcs.get(tgw, set()))
        if not self.attach.get(aid):
            self.serve(aid, "acct")
        if not self.tgw.read(tgw):
            self.flag(aid, "routing not read: every attached account is assumed reachable")
            members = sorted(self.tgw.members.get(tgw, set()) - {self.me})
            if members:
                gid = self.node(f"members:{tgw}", "dest", "group", f"{len(members)} accounts attached to {tgw}",
                                f"route tables not read (owner {self.names.get(owner) or owner or 'unknown'} "
                                "not in this scan): all assumed reachable")  # fmt: skip
                for m in members:
                    self.item(gid, f"{self.names.get(m) or m} ({m})")
                self.link(aid, gid, "both", f"attached to {tgw}", assumed=True)
            return
        table = self.tgw.table_of(att["id"])
        self.item(aid, f"{att['id']} uses route table {table['name'] or table['id']}" if table else
                  f"{att['id']} is associated with no route table: it sends nowhere")  # fmt: skip
        for target, dst in self.tgw.reaches(att["id"]):
            kind, far = self.tgw.far_end(target)
            node = self._tgw_far(kind, far)
            if node and kind == "onprem" and (net := _net(dst)) and net.prefixlen:
                node = self.named_range(net) or node
                self.note_range(net, node, f"transit gateway route to {target}")
            if node:
                default = dst in ("0.0.0.0/0", "::/0")
                self.link(aid, node, "out", f"{dst} → {target}" + (" (default route)" if default else ""))
        for source, dst in self.tgw.reached_by(att["id"]):
            kind, far = self.tgw.far_end(source)
            node = self._tgw_far(kind, far)
            if node:
                self.link(aid, node, "in", f"{source} routes {dst} here")
        for _dst, _target, bh in self.tgw.routes_from(att["id"]):
            if bh:
                self.flag(aid, "blackhole routes in its table")
                break

    def _tgw_far(self, kind: str, far: str) -> str | None:
        if kind == "account" and far:
            return self.account(far)
        if kind == "onprem":
            return self.onprem(far, far.replace("direct-connect-gateway", "Direct Connect gateway").replace(
                "vpn", "VPN", 1), "through the transit gateway")  # fmt: skip
        return None

    def _privatelink(self, region: str, n: dict) -> None:
        owners = {}
        for aid, f in self.scanned.items():
            for nn in (f.get("access_network") or {}).values():
                for s in nn.get("services") or []:
                    owners[s.get("name")] = aid
        from .collectors.access import account_of

        for e in n.get("endpoints") or []:
            nid = self.asset(e["id"], "pl-out", "PrivateLink endpoint", region, e.get("service", ""))
            self._vpcs(nid, e.get("vpc"))
            if not self.attach.get(nid):
                self.serve(nid, "acct")
            provider = owners.get(e.get("service"))
            far = self.account(provider) if provider else self.node(
                f"svc:{e.get('service')}", "dest", "external", e.get("service", "").rsplit(".", 1)[-1],
                "an endpoint service outside the scan")  # fmt: skip
            self.link(nid, far, "out", e.get("service", ""))
        for s in n.get("services") or []:
            nid = self.asset(s["id"], "pl-in", "PrivateLink service", region, s.get("name", ""))
            self.serve(nid, "acct")
            if not s.get("acceptance"):
                self.flag(nid, "connections accepted automatically")
            for p in s.get("allowed") or []:
                src = self.dest("anyone") if p == "*" else None
                if not src:
                    acct = account_of(p)
                    if not acct or acct == self.me:
                        continue
                    src = self.account(acct)
                self.link(nid, src, "in", f"may connect to {s['id']}")

    # ------------------------------------------------------------------ flow-log evidence

    def flows(self, f: dict) -> dict:
        regions = f.get("access_flows") or {}
        if not regions:
            return {"read": False}
        assets = f.get("access_assets") or {}
        own = [n for x in assets.values() for v in x.get("vpcs") or [] for n in map(_net, v.get("cidrs") or []) if n]
        total = attributed = internal = unplaced = 0
        covered_vpcs: set[str] = set()
        s3_only: set[str] = set()
        by_dest: dict[str, dict] = {}
        refused: list[dict] = []
        self.refused_all = refused
        reject_covered: set[str] = set()
        for region, fl in regions.items():
            x = assets.get(region) or {}
            subnets = [(n, s) for s in x.get("subnets") or [] if (n := _net(s.get("cidr")))]
            tables = {t["id"]: t for t in x.get("routes") or []}
            nat_ips = {g.get("private_ip"): g["id"] for g in x.get("nats") or [] if g.get("private_ip")}
            sub_vpc = {s["id"]: s.get("vpc") for s in x.get("subnets") or []}
            for rid in fl.get("covered") or []:
                covered_vpcs.add(rid if rid.startswith("vpc-") else sub_vpc.get(rid) or "")
            s3_only.update(fl.get("s3_only") or [])
            total += int(fl.get("total_bytes") or 0)
            for row in fl.get("rows") or []:
                src, dst = _ip(row.get("src")), _ip(row.get("dst"))
                if not src or not dst:
                    continue
                src_own, dst_own = any(src in n for n in own), any(dst in n for n in own)
                if src_own and dst_own:
                    internal += row["bytes"]
                    continue
                if not src_own and not dst_own:
                    continue
                local, remote, direction = (src, dst, "out") if src_own else (dst, src, "in")
                placed = self._place(local, remote, subnets, tables, nat_ips)
                if not placed:
                    unplaced += row["bytes"]
                    continue
                asset, far = placed
                attributed += row["bytes"]
                lk = self.link(asset, far, direction, "seen in flow logs")
                lk["bytes_out" if direction == "out" else "bytes_in"] += row["bytes"]
                lk["flows"] += row["flows"]
                if len(lk["top"]) < 5:
                    lk["top"].append({"local": str(local), "remote": str(remote), "port": row.get("port"),
                                      "dir": direction, "bytes": row["bytes"]})  # fmt: skip
                d = by_dest.setdefault(far, {"in": 0, "out": 0})
                d[direction] += row["bytes"]
            for row in fl.get("rejected") or []:
                src, dst = _ip(row.get("src")), _ip(row.get("dst"))
                if not src or not dst:
                    continue
                src_own, dst_own = any(src in n for n in own), any(dst in n for n in own)
                if src_own == dst_own:
                    continue
                local, remote, direction = (src, dst, "out") if src_own else (dst, src, "in")
                placed = self._place(local, remote, subnets, tables, nat_ips)
                far = placed[1] if placed else self.dest("internet" if remote.is_global else "net:private")
                if placed:
                    lk = self.link(placed[0], far, direction, "refused traffic in flow logs")
                    lk["rejected"] += row["flows"]
                refused.append({"local": str(local), "remote": str(remote), "port": row.get("port"), "dir": direction,
                                "flows": row["flows"], "to": far, "label": self.nodes[far]["label"],
                                "internet": remote.is_global, "via": placed[0] if placed else None})  # fmt: skip
            reject_covered.update(fl.get("reject_covered") or [])
        covered_vpcs.discard("")
        for lk in self.links.values():
            if self.nodes.get(lk["from"], {}).get("col") != "asset":
                continue
            vpcs = {v.removeprefix("vpc:") for v, ats in self._served().items() if lk["from"] in ats}
            if vpcs and vpcs <= covered_vpcs:
                lk["observed"] = bool(lk["bytes_in"] or lk["bytes_out"])
        hours = next(iter(regions.values())).get("hours", 24)
        top = sorted(by_dest.items(), key=lambda kv: -(kv[1]["in"] + kv[1]["out"]))[:8]
        return {
            "read": True,
            "hours": hours,
            "total_bytes": total,
            "attributed_bytes": attributed,
            "internal_bytes": internal,
            "unplaced_bytes": unplaced,
            "covered_vpcs": sorted(covered_vpcs),
            "uncovered_vpcs": sorted(set(self.vpc_node) - covered_vpcs),
            "s3_only": sorted(s3_only),
            "bytes_in": sum(d["in"] for d in by_dest.values()),
            "bytes_out": sum(d["out"] for d in by_dest.values()),
            "top": [
                {
                    "id": k,
                    "label": self.nodes[k]["label"],
                    "bytes": d["in"] + d["out"],
                    "bytes_in": d["in"],
                    "bytes_out": d["out"],
                }
                for k, d in top
            ],  # fmt: skip
            # refused: what security groups and network ACLs turned away; None when no flow log records it
            "refused": None
            if not reject_covered
            else {
                "flows": sum(r["flows"] for r in refused),
                "in": sum(r["flows"] for r in refused if r["dir"] == "in"),
                "out": sum(r["flows"] for r in refused if r["dir"] == "out"),
                "from_internet": sum(r["flows"] for r in refused if r["dir"] == "in" and r["internet"]),
                "top": sorted(refused, key=lambda r: -r["flows"])[:20],
            },
        }

    # ------------------------------------------------------------ failed and blocked traffic

    def failures(self, f: dict, flows: dict) -> dict:
        """Every kind of refused, blocked, dropped or failed traffic at the account's edge, each with its count
        (0 included) and where it happened, plus who was refused: far addresses from the flow logs, callers
        from CloudTrail, and in how many other scanned accounts each was refused too."""
        regions = f.get("access_failures") or {}
        sums: dict[str, dict] = {}
        present: dict[str, int] = {}
        read_regions = [r for r, x in regions.items() if "metrics" in x]
        refused_regions = sorted(r for r, x in regions.items() if "metrics" not in x and x.get("refused"))
        for region in read_regions:
            x = regions[region]
            for fam, n in (x.get("present") or {}).items():
                present[fam] = present.get(fam, 0) + n
            for key, v in (x.get("metrics") or {}).items():
                cat = FAIL_METRIC_CAT.get(key, key)
                c = sums.setdefault(cat, {"total": 0, "top": []})
                c["total"] += v.get("total") or 0
                for name, val in v.get("top") or []:
                    node = self._fail_node(cat, region, name)
                    c["top"].append({"name": name, "region": region, "value": val, "node": node})
        rows = []
        for key, group, what, direction, fams in FAIL_CATS:
            row = {"key": key, "group": group, "what": what, "dir": direction, "total": 0, "top": []}
            if fams is None:
                pass  # flow-log and CloudTrail rows are filled below
            elif not read_regions:
                row["state"] = "not_read"
                row["note"] = (f"CloudWatch metrics refused in {', '.join(refused_regions)}" if refused_regions
                               else "needs a new scan")  # fmt: skip
            else:
                c = sums.get(key) or {"total": 0, "top": []}
                merged: dict[tuple, dict] = {}
                for t in c["top"]:
                    k = (t["name"], t["region"])
                    merged[k] = {**t, "value": merged.get(k, {}).get("value", 0) + t["value"]}
                row["total"] = c["total"]
                row["top"] = sorted(merged.values(), key=lambda t: -t["value"])[:FAIL_TOP]
                row["resources"] = sum(present.get(x, 0) for x in fams)
                row["state"] = "read" if row["resources"] or row["total"] else "none_here"
                for t in row["top"]:
                    if t["node"] in self.nodes:
                        self.flag(t["node"], f"{_count(t['value'])} {what.lower()} in {FAIL_HOURS}h")
            rows.append(row)
        by_key = {r["key"]: r for r in rows}
        sources = self._refused_sources(flows, by_key)
        callers = self._trail_callers(by_key)
        named = lambda ids: [{"id": a, "name": self.names.get(a) or a} for a in ids]  # noqa: E731
        for x in (*sources["rows"], *callers["rows"]):
            x["elsewhere"] = named(x["elsewhere"])
        return {"hours": FAIL_HOURS, "rows": rows, "sources": sources, "callers": callers,
                "regions": sorted(read_regions), "org": self._org_probes(named)}  # fmt: skip

    def _org_probes(self, named) -> dict:
        """Internet addresses refused in the flow logs, and callers from internet addresses refused by
        CloudTrail, across every scanned account: the same source turned away in several accounts is someone
        mapping the organisation."""
        nets: dict[str, dict] = {}
        for aid, f in self.scanned.items():
            for fl in (f.get("access_flows") or {}).values():
                for r in fl.get("rejected") or []:
                    ip = _ip(r.get("src"))
                    if not ip or not ip.is_global:
                        continue
                    x = nets.setdefault(str(ip), {"ip": str(ip), "accounts": set(), "attempts": 0, "ports": set()})
                    x["accounts"].add(aid)
                    x["attempts"] += r.get("flows") or 0
                    if r.get("port"):
                        x["ports"].add(str(r["port"]))
        calls: dict[str, dict] = {}
        for f in self.scanned.values():
            for r in (f.get("trail_denials") or {}).get("rows") or []:
                ip = _ip(r.get("ip"))
                if not ip or not ip.is_global:
                    continue
                x = calls.setdefault(str(ip), {"ip": str(ip), "accounts": set(), "n": 0, "calls": set(),
                                               "who": set()})  # fmt: skip
                x["accounts"].add(r.get("account"))
                x["n"] += r.get("n") or 0
                x["calls"].add(r.get("call"))
                x["who"].add(r.get("who"))

        def rows(d: dict, weight: str) -> list[dict]:
            top = sorted(d.values(), key=lambda x: (-len(x["accounts"]), -x[weight]))[:SOURCES]
            return [{**x, "accounts": named(sorted(x["accounts"])), "account_count": len(x["accounts"]),
                     **({"ports": sorted(x["ports"], key=lambda p: int(p) if p.isdigit() else 0)[:12],
                         "port_count": len(x["ports"])} if "ports" in x else {}),
                     **({"calls": len(x["calls"]), "who": sorted(x["who"])[:3]} if "calls" in x else {})}
                    for x in top]  # fmt: skip

        flow_read = any(fl.get("reject_covered") for f in self.scanned.values()
                        for fl in (f.get("access_flows") or {}).values())  # fmt: skip
        trail_read = any((f.get("trail_denials") or {}).get("read") for f in self.scanned.values())
        sources, callers = rows(nets, "attempts"), rows(calls, "n")
        for x in sources:
            x["both"] = x["ip"] in calls  # also refused by AWS: probing the network and the APIs alike
        for x in callers:
            x["both"] = x["ip"] in nets
        return {"flows_read": flow_read, "trail_read": trail_read, "sources": sources, "callers": callers}

    def _fail_node(self, cat: str, region: str, name: str) -> str | None:
        if cat.startswith(("alb_", "nlb_")):
            parts = name.split("/")
            return f"lb:{region}:{parts[1]}" if len(parts) > 2 else None
        if cat.startswith("tgw_"):
            return f"tgw:{name}"
        if cat.startswith("api_"):
            return f"api:{region}"
        if cat.startswith(("nat_", "vpce_", "vpcs_")):
            return name
        return None

    def _refused_sources(self, flows: dict, by_key: dict) -> dict:
        """Flow-log rows and the far addresses that were refused, worst first."""
        rf = flows.get("refused") if flows.get("read") else None
        flow_keys = ("flow_in", "flow_internet", "flow_out", "flow_db")
        if rf is None:
            note = ("the flow logs here record accepted traffic only" if flows.get("read")
                    else "flow logs not read: tick Also read VPC flow logs")  # fmt: skip
            for k in flow_keys:
                by_key[k].update(state="not_read", note=note)
            return {"read": False, "rows": []}
        rows = self.refused_all
        db = [r for r in rows if r["dir"] == "in" and str(r.get("port")) in DB_PORTS]
        for k, sel in (("flow_in", [r for r in rows if r["dir"] == "in"]),
                       ("flow_internet", [r for r in rows if r["dir"] == "in" and r["internet"]]),
                       ("flow_out", [r for r in rows if r["dir"] == "out"]), ("flow_db", db)):  # fmt: skip
            by_key[k].update(state="read", total=sum(r["flows"] for r in sel))
            if k == "flow_db":
                tops: dict[str, int] = {}
                for r in sel:
                    name = f"{r['local']} port {r['port']} ({DB_PORTS[str(r['port'])]})"
                    tops[name] = tops.get(name, 0) + r["flows"]
                by_key[k]["top"] = [{"name": n, "value": v, "region": "", "node": None}
                                    for n, v in sorted(tops.items(), key=lambda kv: -kv[1])[:FAIL_TOP]]  # fmt: skip
        elsewhere = self._refused_elsewhere()
        far: dict[tuple, dict] = {}
        for r in rows:
            x = far.setdefault((r["remote"], r["dir"]), {"remote": r["remote"], "dir": r["dir"], "attempts": 0,
                                                         "ports": set(), "targets": set(), "label": r["label"],
                                                         "internet": r["internet"]})  # fmt: skip
            x["attempts"] += r["flows"]
            if r.get("port"):
                x["ports"].add(str(r["port"]))
            x["targets"].add(r["local"])
        out = []
        for x in sorted(far.values(), key=lambda x: -x["attempts"])[:SOURCES]:
            ports = sorted(x["ports"], key=lambda p: int(p) if p.isdigit() else 0)
            out.append({**x, "ports": ports[:12], "port_count": len(ports), "targets": sorted(x["targets"])[:5],
                        "target_count": len(x["targets"]),
                        "elsewhere": sorted(a for a, ips in elsewhere.items() if x["remote"] in ips)})  # fmt: skip
        return {"read": True, "rows": out, "addresses": len(far)}

    def _refused_elsewhere(self) -> dict[str, set[str]]:
        """{other scanned account: every address in its refused flow-log rows}."""
        out = {}
        for aid, f in self.scanned.items():
            if aid == self.me:
                continue
            ips = {ip for fl in (f.get("access_flows") or {}).values() for r in fl.get("rejected") or []
                   for ip in (r.get("src"), r.get("dst")) if ip}  # fmt: skip
            if ips:
                out[aid] = ips
        return out

    def _trail_callers(self, by_key: dict) -> dict:
        """CloudTrail: calls refused against this account, grouped by caller and address."""
        mine, others, covered, totals = [], {}, False, 0
        for aid, f in self.scanned.items():
            t = f.get("trail_denials")
            if not t or not t.get("read"):
                continue
            if t.get("org") or aid == self.me:
                covered = True
            totals += int((t.get("totals") or {}).get(self.me) or 0)
            for r in t.get("rows") or []:
                if r.get("account") == self.me:
                    mine.append(r)
                else:
                    ip = _ip(r.get("ip"))
                    if ip and ip.is_global:  # a private address or a principal name is no evidence of one source
                        others.setdefault(r.get("account"), set()).add(str(ip))
        denied, login = by_key["trail_denied"], by_key["trail_login"]
        if not covered:
            note = ("no trail in the scan delivers to CloudWatch Logs for this account (the management "
                    "account's organisation trail covers every account)")  # fmt: skip
            if not any(f.get("trail_denials") is not None for f in self.scanned.values()):
                note = "CloudTrail not read: tick Also read VPC flow logs (it reads both)"
            for row in (denied, login):
                row.update(state="not_read", note=note)
            return {"read": False, "rows": []}
        logins = [r for r in mine if r.get("call") == "ConsoleLogin"]
        login.update(state="read", total=sum(r["n"] for r in logins))
        denied.update(state="read", total=max(totals - login["total"], sum(r["n"] for r in mine if r not in logins)))
        groups: dict[tuple, dict] = {}
        for r in mine:
            g = groups.setdefault((r.get("who"), r.get("ip")), {"who": r.get("who") or "", "ip": r.get("ip") or "",
                                                                "n": 0, "calls": {}, "services": set(),
                                                                "codes": set()})  # fmt: skip
            g["n"] += r["n"]
            call = f"{(r.get('svc') or '').split('.')[0]}:{r.get('call')}"
            g["calls"][call] = g["calls"].get(call, 0) + r["n"]
            g["services"].add((r.get("svc") or "").split(".")[0])
            g["codes"].add(r.get("code") or ("Failed sign-in" if r.get("call") == "ConsoleLogin" else ""))
        out = []
        for g in sorted(groups.values(), key=lambda g: -g["n"])[:SOURCES]:
            calls = sorted(g["calls"].items(), key=lambda kv: -kv[1])
            out.append({"who": g["who"], "ip": g["ip"], "n": g["n"], "call_count": len(calls),
                        "calls": [c for c, _ in calls[:8]], "services": sorted(g["services"] - {""}),
                        "codes": sorted(g["codes"] - {""}),
                        "elsewhere": sorted(a for a, k in others.items() if g["ip"] in k)})  # fmt: skip
        return {"read": True, "rows": out, "callers": len(groups), "capped": len(mine) >= 1000}

    def _served(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for asset, vpcs in self.attach.items():
            for v in vpcs:
                out.setdefault(v, set()).add(asset)
        return out

    def _place(self, local, remote, subnets, tables, nat_ips) -> tuple[str, str] | None:
        """(asset, destination node) for one conversation, by the local subnet's route to the far address."""
        far_public = remote.is_global
        if str(local) in nat_ips and far_public:
            return nat_ips[str(local)], self.dest("internet")
        subnet = max((s for n, s in subnets if local in n), key=lambda s: _net(s["cidr"]).prefixlen, default=None)
        table = tables.get((subnet or {}).get("rt"))
        if not table:
            return None
        best = None
        for r in table["routes"]:
            net = _net(r["dst"])
            if net and remote in net and not r["blackhole"] and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, r)
        if not best:
            return None
        r = best[1]
        kind, target = r["kind"], r["target"]
        asset = {"tgw": f"tgw:{target}", "vpce": f"vpce:{table['vpc']}"}.get(kind, target)
        if asset not in self.nodes:
            return None
        owner = next((o for n, o in self.cidr_owner if remote in n), None)
        if owner:
            return asset, self.account(owner)
        if far_public:
            return asset, self.dest("internet")
        named = next((label for n, label in self.named if remote in n), None)
        if named:
            return asset, self.named_range(next(n for n, _ in self.named if remote in n))
        if kind in ("vgw", "tgw"):
            far = [lk["to"] for lk in self.links.values() if lk["from"] == asset
                   and self.nodes[lk["to"]]["kind"] == "onprem"]  # fmt: skip
            if len(far) == 1:
                return asset, far[0]
        return asset, self.dest("net:private")
