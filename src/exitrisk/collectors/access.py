"""What can reach each account: the facts behind the Access Graph (read in the "assurance" scan step).

Two kinds of path are recorded, as facts only (no checks):

* network, per region (``facts.access_network[region]``): the account's VPC CIDRs, active VPC
  peerings, transit gateway attachments (with the gateway's owner and the attached resource's owner),
  PrivateLink endpoint services with the principals allowed to connect, the account's own endpoints to
  other accounts' services, and the security-group ingress that admits other accounts' groups or
  addresses outside the account's own VPCs;
* IAM (``facts.access_trusts``): every role trust that names a principal outside the account (another
  account, anyone, any account in the organisation, a SAML or OIDC provider). S3 bucket policy grants
  are kept on each bucket (``grants``) by the bucket read in collectors/assurance.py.

report/access_graph.py turns these into account-to-account edges. Nothing here judges: an edge means
"this path exists", not "this path is wrong".
"""

from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import unquote

from ..aws_session import with_backoff

MAX_ITEMS = 1000  # entries kept per list per region; the list says when it was cut
_ACCOUNT = re.compile(r"^\d{12}$")


def _pages(client, op: str, key: str, **kwargs) -> list:
    def read():
        out: list = []
        if client.can_paginate(op):
            for page in client.get_paginator(op).paginate(**kwargs):
                out.extend(page.get(key) or [])
        else:
            out.extend(getattr(client, op)(**kwargs).get(key) or [])
        return out

    return with_backoff(read)


def _listify(v) -> list:
    return v if isinstance(v, list) else [v] if v else []


def _doc(raw) -> dict:
    if isinstance(raw, str):
        try:
            return json.loads(unquote(raw))
        except ValueError:
            return {}
    return raw or {}


def account_of(principal: str) -> str | None:
    """The 12-digit account of an AWS principal (an id, an account root ARN, a role or user ARN)."""
    p = str(principal).strip()
    if _ACCOUNT.match(p):
        return p
    parts = p.split(":")
    if p.startswith("arn:") and len(parts) > 4 and _ACCOUNT.match(parts[4]):
        return parts[4]
    return None


def _cap(items: list, out: dict, key: str) -> None:
    out[key] = items[:MAX_ITEMS]
    if len(items) > MAX_ITEMS:
        out.setdefault("cut", []).append(key)


# --------------------------------------------------------------------------- policies


def _principals(statement: dict, own: str) -> list[dict]:
    """Who an Allow statement lets in, as {kind, id, external_id, conditions}, own account and services left out.

    kind: "account" (a 12-digit id), "anyone" ("*" with no condition naming the caller's organisation or
    account), "org" ("*" limited to the caller's organisation), "federated" (a SAML or OIDC provider).
    """
    principal = statement.get("Principal")
    cond = statement.get("Condition") or {}
    cond_text = json.dumps(cond).lower()
    keys = sorted({k for op in cond.values() if isinstance(op, dict) for k in op})
    external_id = "sts:externalid" in cond_text
    org_bound = "aws:principalorgid" in cond_text or "aws:principalorgpaths" in cond_text
    named = (
        sorted(set(re.findall(r"\b\d{12}\b", cond_text)))
        if re.search(r"aws:(principal|source)(arn|account)", cond_text)
        else []
    )

    if principal == "*":
        aws, federated = ["*"], []
    elif isinstance(principal, dict):
        aws, federated = _listify(principal.get("AWS")), _listify(principal.get("Federated"))
    else:
        return []
    out = []
    for p in aws:
        if str(p) == "*":
            if named:
                out += [{"kind": "account", "id": a} for a in named if a != own]
            elif org_bound:
                out.append({"kind": "org", "id": "org"})
            else:
                out.append({"kind": "anyone", "id": "*"})
            continue
        acct = account_of(p)
        if acct and acct != own:
            out.append({"kind": "account", "id": acct})
    for f in federated:
        out.append({"kind": "federated", "id": str(f)})
    for o in out:
        o["external_id"] = external_id
        if keys:
            o["conditions"] = keys[:6]
    return out


def role_trusts(role_name: str, trust_doc, own: str) -> list[dict]:
    """Every principal outside the account that ``role_name``'s trust policy lets assume it."""
    out = []
    for st in _listify(_doc(trust_doc).get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow":
            for p in _principals(st, own):
                out.append({"role": role_name, **p})
    return out


def policy_grants(policy, own: str) -> list[dict]:
    """Principals outside the account that a resource policy (a bucket policy) allows, with a few of the actions."""
    seen: dict[tuple, dict] = {}
    for st in _listify(_doc(policy).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in _listify(st.get("Action"))]
        for p in _principals(st, own):
            g = seen.setdefault((p["kind"], p["id"]), {**p, "actions": []})
            g["actions"] = sorted(set(g["actions"]) | set(actions))[:6]
    return list(seen.values())


# --------------------------------------------------------------------------- network


def port_text(perm: dict) -> str:
    proto = str(perm.get("IpProtocol"))
    if proto == "-1":
        return "all traffic"
    name = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto, proto)
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if lo in (None, -1):
        return name
    return f"{name} {lo}" if lo == hi else f"{name} {lo}-{hi}"


def vpc_cidrs(vpcs: list[dict]) -> list[str]:
    out = []
    for v in vpcs:
        for a in v.get("CidrBlockAssociationSet") or [
            {"CidrBlock": v.get("CidrBlock"), "CidrBlockState": {"State": "associated"}}
        ]:
            if a.get("CidrBlock") and (a.get("CidrBlockState") or {}).get("State", "associated") == "associated":
                out.append(a["CidrBlock"])
    return sorted(set(out))


def ingress_sources(groups: list[dict], own: str, own_cidrs: list[str], in_use: set[str] | None) -> dict:
    """Security-group ingress that admits something outside the account.

    ``refs``: rules naming another account's security group. ``cidrs``: IPv4 ranges not inside the
    account's own VPCs (0.0.0.0/0 included), one entry per (cidr, ports) with the groups that carry it.
    Groups attached to nothing (``in_use`` given and the group not in it) are skipped: they admit nothing.
    """
    own_nets = []
    for c in own_cidrs:
        try:
            own_nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    refs: dict[tuple, set] = {}
    cidrs: dict[tuple, set] = {}
    for g in groups:
        gid = g.get("GroupId", "")
        if in_use is not None and gid not in in_use:
            continue
        for perm in g.get("IpPermissions") or []:
            ports = port_text(perm)
            for pair in perm.get("UserIdGroupPairs") or []:
                acct = pair.get("UserId")
                if acct and acct != own:
                    refs.setdefault((acct, pair.get("GroupId", ""), ports), set()).add(gid)
            for r in perm.get("IpRanges") or []:
                try:
                    net = ipaddress.ip_network(r.get("CidrIp", ""), strict=False)
                except ValueError:
                    continue
                if net.prefixlen and any(net.subnet_of(o) for o in own_nets):
                    continue  # traffic from inside the account
                cidrs.setdefault((str(net), ports), set()).add(gid)
    return {
        "refs": [
            {"account": a, "group": rg, "ports": p, "groups": sorted(gs)[:5]} for (a, rg, p), gs in sorted(refs.items())
        ],
        "cidrs": [{"cidr": c, "ports": p, "groups": sorted(gs)[:5]} for (c, p), gs in sorted(cidrs.items())],
    }


def task_access_network(ctx, region: str) -> None:
    """The network paths into and out of the account in ``region``; see the module docstring."""
    ec2 = ctx.client("ec2", region)
    own = ctx.account_id
    out: dict = {}
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    cidrs = vpc_cidrs(vpcs)
    out["cidrs"] = cidrs

    peerings = []
    for p in _pages(ec2, "describe_vpc_peering_connections", "VpcPeeringConnections",
                    Filters=[{"Name": "status-code", "Values": ["active"]}]):  # fmt: skip
        req, acc = p.get("RequesterVpcInfo") or {}, p.get("AccepterVpcInfo") or {}
        peerings.append({
            "id": p.get("VpcPeeringConnectionId"),
            "requester": req.get("OwnerId"), "requester_region": req.get("Region"),
            "requester_cidrs": [c["CidrBlock"] for c in req.get("CidrBlockSet") or [] if c.get("CidrBlock")],
            "accepter": acc.get("OwnerId"), "accepter_region": acc.get("Region"),
            "accepter_cidrs": [c["CidrBlock"] for c in acc.get("CidrBlockSet") or [] if c.get("CidrBlock")],
        })  # fmt: skip
    _cap(peerings, out, "peerings")

    attachments = [
        {
            "id": a.get("TransitGatewayAttachmentId"),
            "tgw": a.get("TransitGatewayId"),
            "tgw_owner": a.get("TransitGatewayOwnerId"),
            "owner": a.get("ResourceOwnerId"),
            "type": a.get("ResourceType"),
            "resource": a.get("ResourceId"),
        }
        for a in _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
        if a.get("State") in ("available", "modifying", "pendingAcceptance", "pending")
    ]
    _cap(attachments, out, "tgw_attachments")

    services = []
    for s in _pages(ec2, "describe_vpc_endpoint_service_configurations", "ServiceConfigurations"):
        if s.get("ServiceState") in ("Deleting", "Deleted", "Failed"):
            continue
        perms = _pages(ec2, "describe_vpc_endpoint_service_permissions", "AllowedPrincipals", ServiceId=s["ServiceId"])
        allowed = [p.get("Principal", "") for p in perms]
        services.append({"id": s["ServiceId"], "name": s.get("ServiceName", ""), "allowed": allowed[:50],
                         "acceptance": bool(s.get("AcceptanceRequired"))})  # fmt: skip
    _cap(services, out, "services")

    endpoints = [
        {"id": e["VpcEndpointId"], "service": e.get("ServiceName", "")}
        for e in _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints")
        if e.get("ServiceName", "").startswith("com.amazonaws.vpce.")
        and e.get("State", "").lower() in ("available", "pendingacceptance", "pending")
    ]
    _cap(endpoints, out, "endpoints")

    enis = _pages(ec2, "describe_network_interfaces", "NetworkInterfaces")
    in_use = {g["GroupId"] for e in enis for g in e.get("Groups") or [] if g.get("GroupId")}
    sources = ingress_sources(_pages(ec2, "describe_security_groups", "SecurityGroups"), own, cidrs, in_use)
    _cap(sources["refs"], out, "sg_refs")
    _cap(sources["cidrs"], out, "sg_cidrs")
    ctx.r.fact("access_network", out, region)
