"""Access Graph: what can reach each account, over the network and through IAM.

Built from the facts the Cloud Assurance step keeps (collectors/access.py). Every edge reads
"FROM can reach TO": a role in TO trusts FROM, a bucket in TO grants FROM, a security group in TO
admits FROM's addresses or groups over a route that exists, FROM's VPC is peered with TO's, FROM
connects to TO's PrivateLink service. The console walks the edges a chosen number of hops from the
selected account; this module only builds them, so the walk needs no new request.

Transit gateways are followed through their route tables when the gateway's owner was scanned: an
account reaches another when the table associated with its attachment routes to the other's
attachment. Without the tables the gateway is a hub: every attached account reaches every other,
which the console counts as one hop between accounts, not two.
"""

from __future__ import annotations

import ipaddress
import time

from .filtering import AccountFilter
from .logging_config import get_logger

log = get_logger("access_graph")

DETAILS = 12  # detail lines kept per edge; the count is kept in full

# Each kind of edge: the label, whether it is a network or an IAM path, and what it means.
TYPES = {
    "role-trust": ("Role trust", "iam", "A role in the target account trusts the source to assume it"),
    "bucket-policy": ("Bucket policy", "iam", "A bucket policy in the target account allows the source"),
    "tgw": ("Transit gateway", "network",
            "The transit gateway routes the source to the target (or, routing not read, both are attached)"),
    "peering": ("VPC peering", "network", "A VPC of the source is peered with a VPC of the target"),
    "privatelink": ("PrivateLink", "network",
                    "The source connects to, or may connect to, an endpoint service of the target"),
    "sg-ref": ("Security group reference", "network",
               "A security group in the target admits a security group of the source"),
    "sg-cidr": ("Security group range", "network",
                "A security group in the target admits the source's VPC addresses, and a route between them exists"),
    "internet": ("Open to the internet", "network", "A security group in the target admits any address (0.0.0.0/0)"),
}  # fmt: skip

SPECIAL = {
    "internet": ("The internet", "internet", "Any address: 0.0.0.0/0"),
    "anyone": ("Anyone", "anyone", "Any AWS principal, no condition naming who"),
    "org": ("Any account in the organisation", "org-any", "Allowed with aws:PrincipalOrgID or aws:PrincipalOrgPaths"),
    "net:private": ("Other private networks", "network",
                    "Private ranges outside every scanned VPC: on-premises, partners, or accounts not scanned"),
    "net:public": ("Specific internet addresses", "network", "Public ranges narrower than 0.0.0.0/0"),
}  # fmt: skip


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, nid: str, label: str, kind: str, sub: str = "") -> None:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "label": label, "kind": kind, "sub": sub}

    def edge(self, src: str, dst: str, etype: str, detail: str, region: str | None = None) -> None:
        if src == dst:
            return
        e = self.edges.get((src, dst, etype))
        if e is None:
            label, kind, _ = TYPES[etype]
            e = self.edges[(src, dst, etype)] = {"from": src, "to": dst, "type": etype, "kind": kind, "label": label,
                                                 "details": [], "count": 0, "regions": []}  # fmt: skip
        if detail not in e["details"]:
            e["count"] += 1
            if len(e["details"]) < DETAILS:
                e["details"].append(detail)
        if region and region not in e["regions"]:
            e["regions"].append(region)


def _nets(cidrs) -> list[ipaddress.IPv4Network]:
    out = []
    for c in cidrs or []:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            out.append(net)
    return out


def build_access(scan: dict, account_filter: AccountFilter | None = None) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    checked = (scan.get("assurance") or {}).get("accounts") or {}
    org_accounts = scan.get("org_accounts") or {}
    names = {a["id"]: a.get("name", "") for a in scan.get("accounts") or []}
    names.update({k: v.get("name", "") for k, v in org_accounts.items() if k not in names})
    base = {
        "scan_id": scan.get("id"),
        "label": scan.get("label", ""),
        "scan_at": scan.get("created_at"),
        "filter": account_filter.describe() if account_filter.active else "",
        "types": {k: {"label": v[0], "kind": v[1], "what": v[2]} for k, v in TYPES.items()},
    }
    if not checked:
        return {**base, "available": False, "nodes": [], "edges": [], "accounts": [],
                "reason": "This scan has no Cloud Assurance checks. The Access Graph is read with them: run a new "
                          "scan with Cloud Assurance ticked."}  # fmt: skip
    scanned = {
        aid: res.get("facts") or {} for aid, res in checked.items() if account_filter.matches(names.get(aid, aid))
    }
    with_facts = {aid for aid, f in scanned.items() if "access_network" in f or "access_trusts" in f}
    if not with_facts:
        return {**base, "available": False, "nodes": [], "edges": [], "accounts": [],
                "reason": "This scan was made before the Access Graph existed. Run a new scan with Cloud Assurance "
                          "ticked to read the network paths and role trusts."}  # fmt: skip

    g = _Graph()

    def account_node(aid: str) -> str:
        if aid in scanned:
            g.node(aid, names.get(aid) or aid, "scanned", aid)
        elif aid in org_accounts or aid in names:
            g.node(aid, names.get(aid) or aid, "org", f"{aid} · in the organisation, not in this report")
        else:
            g.node(aid, aid, "external", "outside the organisation")
        return aid

    def special(key: str) -> str:
        label, kind, sub = SPECIAL[key]
        g.node(key, label, kind, sub)
        return key

    def principal_node(p: dict) -> str | None:
        kind = p.get("kind")
        if kind == "account":
            return account_node(p["id"])
        if kind in ("anyone", "org"):
            return special(kind)
        if kind == "federated":
            pid = p["id"]
            short = pid.split(":oidc-provider/")[-1].split(":saml-provider/")[-1]
            g.node(f"fed:{pid}", short, "federated", "SAML or OIDC identity provider")
            return f"fed:{pid}"
        return None

    for aid in scanned:
        account_node(aid)

    # ---------------------------------------------------------------- IAM
    for aid, facts in scanned.items():
        for t in facts.get("access_trusts") or []:
            src = principal_node(t)
            if src:
                extra = " (external id)" if t.get("external_id") else ""
                g.edge(src, aid, "role-trust", f"role {t['role']}{extra}")
        for b in facts.get("buckets") or []:
            for gr in b.get("grants") or []:
                src = principal_node(gr)
                if src:
                    acts = ", ".join(gr.get("actions") or [])
                    g.edge(src, aid, "bucket-policy", f"bucket {b['name']}" + (f": {acts}" if acts else ""))

    # ---------------------------------------------------------------- network
    nets = {aid: f.get("access_network") or {} for aid, f in scanned.items()}
    cidr_owner: list[tuple[ipaddress.IPv4Network, str]] = []
    tgw_members: dict[str, set[str]] = {}
    tgw_owner: dict[str, str] = {}
    peers: set[frozenset] = set()
    service_owner: dict[str, str] = {}

    for aid, regions in nets.items():
        for n in regions.values():
            cidr_owner += [(net, aid) for net in _nets(n.get("cidrs"))]
            for a in n.get("tgw_attachments") or []:
                if not a.get("tgw"):
                    continue
                tgw_owner[a["tgw"]] = a.get("tgw_owner") or tgw_owner.get(a["tgw"], "")
                members = tgw_members.setdefault(a["tgw"], set())
                for who in (a.get("owner"), a.get("tgw_owner")):
                    if who:
                        members.add(who)
            for s in n.get("services") or []:
                if s.get("name"):
                    service_owner[s["name"]] = aid

    from .account_map import TgwRouting

    routing = TgwRouting(scanned)
    tgw_pairs: dict[str, set[tuple[str, str]]] = {}  # gateway -> (from, to) accounts its route tables allow
    for att, a in routing.atts.items():
        if not routing.read(a.get("tgw", "")) or not a.get("owner"):
            continue
        for target, dst in routing.reaches(att):
            kind, far = routing.far_end(target)
            if kind == "account" and far and far != a["owner"]:
                tgw_pairs.setdefault(a["tgw"], set()).add((a["owner"], far))
                g.edge(account_node(a["owner"]), account_node(far), "tgw", f"{a['tgw']}: {dst} to {target}")

    def tgw_shared(a: str, b: str) -> list[str]:
        out = []
        for t, m in tgw_members.items():
            if routing.read(t):
                if (a, b) in tgw_pairs.get(t, set()) or (b, a) in tgw_pairs.get(t, set()):
                    out.append(t)
            elif a in m and b in m:
                out.append(t)
        return out

    for regions in nets.values():
        for region, n in regions.items():
            for p in n.get("peerings") or []:
                a, b = p.get("requester"), p.get("accepter")
                if a and b and a != b:
                    peers.add(frozenset((a, b)))
                    for x, y in ((a, b), (b, a)):
                        g.edge(account_node(x), account_node(y), "peering", f"{p['id']} ({region})", region)

    for tgw, members in tgw_members.items():
        if routing.read(tgw):
            continue  # followed through its route tables above: account to account edges
        owner = tgw_owner.get(tgw, "")
        hub = f"tgw:{tgw}"
        g.node(hub, tgw, "tgw", f"transit gateway owned by {names.get(owner) or owner or 'unknown'}; routing not "
                                "read, so every attachment is assumed to reach every other")  # fmt: skip
        for m in members:
            account_node(m)
            g.edge(m, hub, "tgw", f"attached to {tgw}")
            g.edge(hub, m, "tgw", f"attached to {tgw}")

    def routed(a: str, b: str) -> list[str]:
        how = [f"via {t}" for t in tgw_shared(a, b)]
        if frozenset((a, b)) in peers:
            how.append("via VPC peering")
        return how

    for aid, regions in nets.items():
        for region, n in regions.items():
            for s in n.get("services") or []:
                for principal in s.get("allowed") or []:
                    if principal == "*":
                        src = special("anyone")
                    else:
                        from .collectors.access import account_of

                        acct = account_of(principal)
                        if not acct or acct == aid:
                            continue
                        src = account_node(acct)
                    note = "" if s.get("acceptance") else ", accepted automatically"
                    g.edge(src, aid, "privatelink", f"may connect to {s['id']}{note} ({region})", region)
            for e in n.get("endpoints") or []:
                provider = service_owner.get(e.get("service", ""))
                if provider and provider != aid:
                    what = f"{e['id']} connects to {e['service']} ({region})"
                    g.edge(aid, account_node(provider), "privatelink", what, region)
            for ref in n.get("sg_refs") or []:
                src = account_node(ref["account"])
                what = f"{', '.join(ref.get('groups') or [])} admit {ref['group']} on {ref['ports']} ({region})"
                g.edge(src, aid, "sg-ref", what, region)
            for rule in n.get("sg_cidrs") or []:
                try:
                    net = ipaddress.ip_network(rule["cidr"], strict=False)
                except ValueError:
                    continue
                groups = ", ".join(rule.get("groups") or [])
                if net.prefixlen == 0:
                    what = f"{groups} admit any address on {rule['ports']} ({region})"
                    g.edge(special("internet"), aid, "internet", what, region)
                    continue
                owners = sorted({o for vnet, o in cidr_owner if o != aid and vnet.overlaps(net)})
                matched = False
                for o in owners:
                    how = routed(o, aid)
                    if how:
                        matched = True
                        g.edge(
                            account_node(o),
                            aid,
                            "sg-cidr",
                            f"{groups} admit {rule['cidr']} on {rule['ports']} {'; '.join(how)} ({region})",
                            region,
                        )
                if not matched:
                    key = "net:private" if net.is_private else "net:public"
                    g.edge(
                        special(key),
                        aid,
                        "internet" if key == "net:public" else "sg-cidr",
                        f"{groups} admit {rule['cidr']} on {rule['ports']} ({region})",
                        region,
                    )

    edges = sorted(g.edges.values(), key=lambda e: (e["to"], e["from"], e["type"]))
    indeg: dict[str, int] = {}
    for e in edges:
        if e["kind"] and not e["from"].startswith("tgw:"):
            indeg[e["to"]] = indeg.get(e["to"], 0) + 1
    accounts = sorted(
        (
            {"id": aid, "name": names.get(aid) or aid, "in": indeg.get(aid, 0), "read": aid in with_facts}
            for aid in scanned
        ),  # fmt: skip
        key=lambda a: (-a["in"], a["name"]),
    )
    cut = sorted({f"{aid} {region}: {', '.join(n['cut'])}" for aid, regions in nets.items()
                  for region, n in regions.items() if n.get("cut")})  # fmt: skip
    notes = []
    if cut:
        notes.append(f"Some lists were cut at their limit and the graph may miss paths: {'; '.join(cut[:5])}")
    missing = sorted(set(scanned) - with_facts)
    if missing:
        notes.append(f"{len(missing)} account(s) in this report were read without the Access Graph facts (an "
                     "older scan or a refused call): edges into them are missing.")  # fmt: skip
    log.info("access graph: %d nodes, %d edges in %.2fs", len(g.nodes), len(edges), time.perf_counter() - started)
    return {
        **base,
        "available": True,
        "nodes": sorted(g.nodes.values(), key=lambda n: (n["kind"], n["label"])),
        "edges": edges,
        "accounts": accounts,
        "notes": notes,
        "stats": {
            "accounts": len(scanned),
            "nodes": len(g.nodes),
            "edges": len(edges),
            "iam": sum(1 for e in edges if e["kind"] == "iam"),
            "network": sum(1 for e in edges if e["kind"] == "network"),
            "external": sum(1 for n in g.nodes.values() if n["kind"] == "external"),
            "internet_exposed": len({e["to"] for e in edges if e["from"] in ("internet", "anyone")}),
        },
    }
