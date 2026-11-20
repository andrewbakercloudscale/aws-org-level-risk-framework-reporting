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

from botocore.exceptions import ClientError

from ..aws_session import with_backoff
from ..issues import describe_exception, failure_kind
from ..logging_config import get_logger

log = get_logger("access")

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


# Condition keys that tie a resource policy to a network or an organisation.
_LIMIT_KEYS = {
    "aws:sourcevpce": "vpce", "aws:sourcevpc": "vpc", "aws:sourceip": "ip", "aws:vpcsourceip": "ip",
    "aws:principalorgid": "org", "aws:principalorgpaths": "org", "aws:resourceorgid": "org",
}  # fmt: skip


def policy_limits(policy) -> dict:
    """The networks and organisation a resource policy (a bucket policy) holds access to.

    Read only where the meaning is certain: a Deny with a negated condition (StringNotEquals,
    NotIpAddress...) for every caller and every action refuses every request not from these, whatever
    other statements allow. An Allow with a condition limits only itself, so it is not counted.
    Returns {vpce: [...], vpc: [...], ip: [...], org: [...]}, kinds with nothing left out.
    """
    out: dict[str, set] = {}
    for st in _listify(_doc(policy).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Deny":
            continue
        # every caller and every action, or the limit covers only part of the access
        if st.get("Principal") not in ("*", {"AWS": "*"}) or not {"*", "s3:*"} & set(_listify(st.get("Action"))):
            continue
        for op, conds in (st.get("Condition") or {}).items():
            if not isinstance(conds, dict) or "Not" not in op.split(":")[-1]:
                continue
            for key, values in conds.items():
                kind = _LIMIT_KEYS.get(key.lower())
                if kind:
                    out.setdefault(kind, set()).update(str(v) for v in _listify(values))
    return {k: sorted(v)[:10] for k, v in sorted(out.items())}


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
    account's own VPCs (0.0.0.0/0 included), one entry per (cidr, ports) with the groups that carry it, and
    ::/0, any IPv6 address (other IPv6 ranges are not read).
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
            if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges") or []):
                cidrs.setdefault(("::/0", ports), set()).add(gid)
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
        {"id": e["VpcEndpointId"], "service": e.get("ServiceName", ""), "vpc": e.get("VpcId")}
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


# --------------------------------------------------------------------------- the account map
#
# ``facts.access_assets[region]``: every asset that moves data in or out of the account's networks, so one
# account holder can see their own ways in and out and where each leads (report/account_map.py).
# Optional reads (Direct Connect, API Gateway, AWS Transfer, transit gateway routing) that are refused are
# named in ``refused``; the rest of the map still stands.

_ROUTE_TARGETS = (  # route key, kind of target
    ("TransitGatewayId", "tgw"),
    ("NatGatewayId", "nat"),
    ("VpcPeeringConnectionId", "pcx"),
    ("EgressOnlyInternetGatewayId", "eigw"),
    ("NetworkInterfaceId", "eni"),
    ("InstanceId", "instance"),
    ("LocalGatewayId", "lgw"),
    ("CarrierGatewayId", "cgw"),
    ("CoreNetworkArn", "cloudwan"),
)


def route_target(route: dict) -> tuple[str, str] | None:
    """(kind, id) of where a VPC route sends traffic; None for the VPC's own local route."""
    for key, kind in _ROUTE_TARGETS:
        if route.get(key):
            return kind, route[key]
    gw = route.get("GatewayId") or ""
    if gw == "local" or not gw:
        return None
    kind = {"igw": "igw", "vgw": "vgw", "vpce": "vpce"}.get(gw.split("-", 1)[0], "gateway")
    return kind, gw


def route_tables(tables: list[dict]) -> tuple[list[dict], dict[str, str]]:
    """Each route table's routes that leave the VPC, and which table each subnet uses (main table for the rest)."""
    out, subnet_rt = [], {}
    for t in tables:
        main = any(a.get("Main") for a in t.get("Associations") or [])
        subnets = [a["SubnetId"] for a in t.get("Associations") or [] if a.get("SubnetId")]
        for s in subnets:
            subnet_rt[s] = t["RouteTableId"]
        routes = []
        for r in t.get("Routes") or []:
            target = route_target(r)
            dst = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or r.get("DestinationPrefixListId")
            if target and dst:
                routes.append({"dst": dst, "kind": target[0], "target": target[1],
                               "blackhole": r.get("State") == "blackhole"})  # fmt: skip
        out.append({"id": t["RouteTableId"], "vpc": t.get("VpcId"), "main": main, "subnets": len(subnets),
                    "routes": routes[:200]})  # fmt: skip
    return out, subnet_rt


def _name(tags) -> str:
    return next((t.get("Value", "") for t in tags or [] if t.get("Key") == "Name"), "")


def _soft(out: dict, what: str, fn):
    """``fn()``, or None with ``what`` named in ``out['refused']`` when the call is refused or not offered."""
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        return fn()
    except (ClientError, BotoCoreError) as exc:
        code = exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else type(exc).__name__
        out.setdefault("refused", []).append(f"{what} ({code})")
        return None


def _tgw_tables(ec2, out: dict) -> list[dict]:
    """Route tables of the transit gateways this account owns: associations, propagations, routes."""
    tables = []
    for t in _pages(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"):
        if t.get("State") not in ("available", "pending", "modifying"):
            continue
        rid = t["TransitGatewayRouteTableId"]
        assoc = _pages(ec2, "get_transit_gateway_route_table_associations", "Associations",
                       TransitGatewayRouteTableId=rid)  # fmt: skip
        prop = _pages(ec2, "get_transit_gateway_route_table_propagations", "TransitGatewayRouteTablePropagations",
                      TransitGatewayRouteTableId=rid)  # fmt: skip
        found = with_backoff(lambda rid=rid: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rid, Filters=[{"Name": "state", "Values": ["active", "blackhole"]}],
            MaxResults=1000))  # fmt: skip
        routes = [
            {
                "dst": r.get("DestinationCidrBlock") or r.get("PrefixListId", ""),
                "attachments": [a.get("TransitGatewayAttachmentId") for a in r.get("TransitGatewayAttachments") or []],
                "type": r.get("Type", ""),
                "blackhole": r.get("State") == "blackhole",
            }
            for r in found.get("Routes") or []
        ]
        tables.append({"id": rid, "tgw": t.get("TransitGatewayId"), "name": _name(t.get("Tags")),
                       "associations": [a.get("TransitGatewayAttachmentId") for a in assoc],
                       "propagations": [p.get("TransitGatewayAttachmentId") for p in prop],
                       "routes": routes[:500], "routes_cut": bool(found.get("AdditionalRoutesAvailable"))})  # fmt: skip
    return tables


def task_access_assets(ctx, region: str) -> None:
    """The account's ways in and out in ``region``: gateways, routes, public endpoints; see the section note."""
    ec2 = ctx.client("ec2", region)
    out: dict = {}
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    _cap([{"id": v["VpcId"], "name": _name(v.get("Tags")), "cidrs": vpc_cidrs([v]), "default": bool(v.get("IsDefault"))}
          for v in vpcs], out, "vpcs")  # fmt: skip
    tables, subnet_rt = route_tables(_pages(ec2, "describe_route_tables", "RouteTables"))
    main_rt = {t["vpc"]: t["id"] for t in tables if t["main"]}
    _cap(tables, out, "routes")
    subnets = _pages(ec2, "describe_subnets", "Subnets")
    _cap([{"id": s["SubnetId"], "vpc": s.get("VpcId"), "cidr": s.get("CidrBlock"),
           "rt": subnet_rt.get(s["SubnetId"]) or main_rt.get(s.get("VpcId"))}
          for s in subnets], out, "subnets")  # fmt: skip
    _cap([{"id": g["InternetGatewayId"], "vpc": a.get("VpcId")}
          for g in _pages(ec2, "describe_internet_gateways", "InternetGateways")
          for a in g.get("Attachments") or []
          if a.get("State") in ("available", "attached")], out, "igws")  # fmt: skip
    _cap([{"id": g["EgressOnlyInternetGatewayId"], "vpc": a.get("VpcId")}
          for g in _pages(ec2, "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways")
          for a in g.get("Attachments") or []
          if a.get("State") in ("available", "attached")], out, "eigws")  # fmt: skip
    nats = []
    for n in _pages(ec2, "describe_nat_gateways", "NatGateways",
                    Filter=[{"Name": "state", "Values": ["available", "pending"]}]):  # fmt: skip
        addr = (n.get("NatGatewayAddresses") or [{}])[0]
        nats.append({"id": n["NatGatewayId"], "vpc": n.get("VpcId"), "subnet": n.get("SubnetId"),
                     "type": n.get("ConnectivityType", "public"), "public_ip": addr.get("PublicIp"),
                     "private_ip": addr.get("PrivateIp")})  # fmt: skip
    _cap(nats, out, "nats")
    _cap([{"id": g["VpnGatewayId"], "vpcs": [a["VpcId"] for a in g.get("VpcAttachments") or []
                                             if a.get("State") == "attached"], "asn": g.get("AmazonSideAsn")}
          for g in _pages(ec2, "describe_vpn_gateways", "VpnGateways")
          if g.get("State") == "available"], out, "vgws")  # fmt: skip
    cgw_ip = {c["CustomerGatewayId"]: c.get("IpAddress") for c in _pages(ec2, "describe_customer_gateways",
                                                                         "CustomerGateways")}  # fmt: skip
    vpns = []
    for v in _pages(ec2, "describe_vpn_connections", "VpnConnections"):
        if v.get("State") not in ("available", "pending"):
            continue
        tunnels = v.get("VgwTelemetry") or []
        vpns.append({"id": v["VpnConnectionId"], "gateway": v.get("TransitGatewayId") or v.get("VpnGatewayId"),
                     "customer_ip": cgw_ip.get(v.get("CustomerGatewayId")), "name": _name(v.get("Tags")),
                     "tunnels": len(tunnels), "up": sum(1 for t in tunnels if t.get("Status") == "UP"),
                     # static routes: the on-premises ranges sent down the tunnel
                     "routes": [r["DestinationCidrBlock"] for r in v.get("Routes") or []
                                if r.get("DestinationCidrBlock") and r.get("State") != "deleted"][:50]})  # fmt: skip
    _cap(vpns, out, "vpns")
    peer_atts = _soft(out, "transit gateway peerings", lambda: _pages(
        ec2, "describe_transit_gateway_peering_attachments", "TransitGatewayPeeringAttachments"))  # fmt: skip
    if peer_atts is not None:
        mine = []
        for p in peer_atts:
            if p.get("State") not in ("available", "pendingAcceptance", "pending", "modifying"):
                continue
            req, acc = p.get("RequesterTgwInfo") or {}, p.get("AccepterTgwInfo") or {}
            near, far = (req, acc) if req.get("OwnerId") == ctx.account_id else (acc, req)
            mine.append({"id": p["TransitGatewayAttachmentId"], "tgw": near.get("TransitGatewayId"),
                         "peer_tgw": far.get("TransitGatewayId"), "peer_owner": far.get("OwnerId"),
                         "peer_region": far.get("Region")})  # fmt: skip
        _cap(mine, out, "tgw_peerings")
    tgw_tables = _soft(out, "transit gateway route tables", lambda: _tgw_tables(ec2, out))
    if tgw_tables is not None:
        _cap(tgw_tables, out, "tgw_tables")

    endpoints = []
    for e in _pages(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        service = e.get("ServiceName", "")
        if not service.startswith("com.amazonaws.") or service.startswith("com.amazonaws.vpce."):
            continue
        if e.get("State", "").lower() not in ("available", "pending", "pendingacceptance"):
            continue
        endpoints.append({"id": e["VpcEndpointId"], "service": service.rsplit(".", 1)[-1], "vpc": e.get("VpcId"),
                          "type": e.get("VpcEndpointType", ""),
                          "open_policy": _open_policy(e.get("PolicyDocument"))})  # fmt: skip
    _cap(endpoints, out, "aws_endpoints")

    public = []
    for n in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces",
                    Filters=[{"Name": "association.public-ip", "Values": ["*"]}]):  # fmt: skip
        ip = (n.get("Association") or {}).get("PublicIp")
        if ip:
            public.append({"id": n["NetworkInterfaceId"], "ip": ip, "vpc": n.get("VpcId"),
                           "private_ip": n.get("PrivateIpAddress"), "what": eni_kind(n),
                           "groups": [g["GroupId"] for g in n.get("Groups") or []][:5]})  # fmt: skip
    _cap(public, out, "public_ips")

    v2 = ctx.client("elbv2", region)
    lbs = _soft(out, "load balancers", lambda: _pages(v2, "describe_load_balancers", "LoadBalancers"))
    if lbs is not None:
        _cap([{"name": lb.get("LoadBalancerName"), "type": lb.get("Type"), "vpc": lb.get("VpcId"),
               "dns": lb.get("DNSName")}
              for lb in lbs if lb.get("Scheme") == "internet-facing"], out, "lbs")  # fmt: skip
    apis = _soft(out, "API Gateway", lambda: _apis(ctx, region))
    if apis is not None:
        _cap(apis, out, "apis")
    servers = _soft(out, "AWS Transfer", lambda: _pages(ctx.client("transfer", region), "list_servers", "Servers"))
    if servers is not None:
        _cap([{"id": s.get("ServerId"), "endpoint": s.get("EndpointType", ""), "state": s.get("State", "")}
              for s in servers if s.get("State") not in ("OFFLINE", "STOP_FAILED")], out, "transfer")  # fmt: skip
    vifs = _soft(out, "Direct Connect", lambda: ctx.client("directconnect", region).describe_virtual_interfaces())
    if vifs is not None:
        _cap([{"id": v.get("virtualInterfaceId"), "name": v.get("virtualInterfaceName", ""),
               "type": v.get("virtualInterfaceType", ""), "location": v.get("location", ""),
               "gateway": v.get("directConnectGatewayId") or v.get("virtualGatewayId") or "",
               "state": v.get("virtualInterfaceState", "")}
              for v in vifs.get("virtualInterfaces") or []
              if v.get("virtualInterfaceState") in ("available", "pending", "confirming", "verifying")],
             out, "dx_vifs")  # fmt: skip
    fns = _soft(out, "Lambda functions", lambda: _pages(ctx.client("lambda", region), "list_functions", "Functions"))
    if fns is not None:
        _cap(_lambdas(ctx, region, fns, out), out, "lambdas")
    ctx.r.fact("access_assets", out, region)


MAX_URL_READS = 300  # function URL lookups per region (one call each); later functions say "not read"


def _lambdas(ctx, region: str, fns: list[dict], out: dict) -> list[dict]:
    """Each function: its VPC and subnets (where its traffic leaves from), and its function URL's auth type.
    A function outside a VPC reaches the internet through AWS; one in a VPC only through its subnets' routes."""
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    client = ctx.client("lambda", region)
    rows = []
    for f in fns:
        vpc = (f.get("VpcConfig") or {}).get("VpcId") or ""
        rows.append({"name": f.get("FunctionName"), "runtime": f.get("Runtime") or f.get("PackageType", ""),
                     "vpc": vpc, "subnets": (f.get("VpcConfig") or {}).get("SubnetIds") or [],
                     "groups": ((f.get("VpcConfig") or {}).get("SecurityGroupIds") or [])[:5]})  # fmt: skip
    refused = []

    def url(row: dict) -> None:
        if refused:
            return
        try:
            cfgs = client.list_function_url_configs(FunctionName=row["name"]).get("FunctionUrlConfigs") or []
            row["url"] = cfgs[0].get("AuthType") if cfgs else ""
        except Exception as exc:  # noqa: BLE001 - one refusal stops the rest; the function says "not read"
            if "AccessDenied" in str(exc):
                refused.append(1)
            log.debug("function URL of %s not read: %s", row["name"], exc)

    with ThreadPoolExecutor(max_workers=6) as pool:
        # a context copy each: one Context cannot be entered by two threads at once
        for fut in [pool.submit(contextvars.copy_context().run, url, r) for r in rows[:MAX_URL_READS]]:
            fut.result()
    if refused:
        out.setdefault("refused", []).append("Lambda function URLs")
    return rows


def _open_policy(raw) -> bool:
    for st in _listify(_doc(raw).get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow" and st.get("Principal") in ("*", {"AWS": "*"}):
            if str(st.get("Action")) in ("*", "['*']") and not st.get("Condition"):
                return True
    return False


def eni_kind(eni: dict) -> str:
    """What a network interface with a public address belongs to, in a few words."""
    desc = eni.get("Description") or ""
    kind = eni.get("InterfaceType") or ""
    if kind == "nat_gateway" or desc.startswith("Interface for NAT Gateway"):
        return "NAT gateway"
    if desc.startswith("ELB "):
        return "load balancer"
    if (eni.get("Attachment") or {}).get("InstanceId"):
        return "EC2 instance"
    if desc.startswith("RDSNetworkInterface"):
        return "RDS database"
    if desc.startswith("arn:aws:ecs") or eni.get("RequesterId") == "ecs":
        return "ECS task"
    if kind and kind != "interface":
        return kind.replace("_", " ")
    return desc[:40] or "network interface"


def _apis(ctx, region: str) -> list[dict]:
    out = []
    for a in _pages(ctx.client("apigateway", region), "get_rest_apis", "items"):
        kinds = (a.get("endpointConfiguration") or {}).get("types") or ["EDGE"]
        out.append({"id": a["id"], "name": a.get("name", ""), "kind": "REST", "endpoint": kinds[0],
                    "default_endpoint": not a.get("disableExecuteApiEndpoint")})  # fmt: skip
    for a in _pages(ctx.client("apigatewayv2", region), "get_apis", "Items"):
        out.append({"id": a["ApiId"], "name": a.get("Name", ""), "kind": a.get("ProtocolType", "HTTP"),
                    "endpoint": "REGIONAL", "default_endpoint": not a.get("DisableExecuteApiEndpoint")})  # fmt: skip
    return out


# --------------------------------------------------------------------------- flow-log evidence
#
# ``facts.access_flows[region]``: what really crossed the account's VPC edges in the last FLOW_HOURS, read
# with one CloudWatch Logs Insights query per flow-log format. Only when the scan asks for it (it costs
# Insights' per-GB scan price): the largest FLOW_ROWS conversations by bytes, and the total, so the map
# can say how much of the traffic it accounts for. Flow logs delivered only to S3 are named, not read.

FLOW_HOURS = 24
FLOW_ROWS = 2000
FLOW_WAIT = 120  # seconds one query may run before it is stopped
_NEEDED = ("srcaddr", "dstaddr", "dstport", "bytes", "action")
DEFAULT_FORMAT = ("${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} "
                  "${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}")  # fmt: skip


def flow_query(log_format: str, action: str = "ACCEPT") -> str | None:
    """The Insights query for one flow-log format and action (ACCEPT or REJECT), or None when the format
    lacks the fields it needs."""
    fields = [f.strip("${}").replace("-", "_") for f in (log_format or DEFAULT_FORMAT).split()]
    if not set(_NEEDED) <= set(fields):
        return None
    src = "pkt_srcaddr" if "pkt_srcaddr" in fields else "srcaddr"
    dst = "pkt_dstaddr" if "pkt_dstaddr" in fields else "dstaddr"
    names = [f"f_{f}" for f in fields]
    return (
        f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join(names)}'
        f' | filter f_action = "{action}" and f_{src} != "-"'
        f" | stats sum(f_bytes) as bytes, count(*) as flows by f_{src} as src, f_{dst} as dst, f_dstport as port"
        f" | sort {'flows' if action == 'REJECT' else 'bytes'} desc | limit {FLOW_ROWS}"
    )


PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")


def internet_query(log_format: str) -> str | None:
    """Every accepted connection of the day, totalled by whether each end is a private address: the account's
    whole traffic (the total the map compares with), and its traffic with the internet, with how many internet
    addresses it reached (count_distinct, which Insights estimates when there are very many). Read in the same
    query as the total, so it scans nothing more."""
    query = flow_query(log_format)
    if not query:
        return None
    src, dst = re.findall(r"by (f_\w+) as src, (f_\w+) as dst", query)[0]

    def private(f: str) -> str:
        return "(" + " or ".join(f'isIpv4InSubnet({f}, "{c}")' for c in PRIVATE_V4) + ")"

    return (
        query.split(" | stats")[0] + f" | fields {private(src)} as src_private, {private(dst)} as dst_private"
        f" | stats sum(f_bytes) as bytes, count(*) as flows, count_distinct({dst}) as dsts,"
        f" count_distinct({src}) as srcs by src_private, dst_private"
    )


def _add_internet(out: dict, rows: list[dict]) -> None:
    """``out["internet"]``: sent to the internet (a private source, a public target) and received from it."""
    net = out.setdefault("internet", {"out": {"bytes": 0, "flows": 0, "ips": 0}, "in": {"bytes": 0, "flows": 0,
                                                                                       "ips": 0}})  # fmt: skip
    for r in rows:
        sp, dp = str(r.get("src_private")), str(r.get("dst_private"))
        if sp == "1" and dp == "0":
            x, ips = net["out"], _num(r.get("dsts"))
        elif sp == "0" and dp == "1":
            x, ips = net["in"], _num(r.get("srcs"))
        else:
            continue
        x["bytes"] += _num(r.get("bytes"))
        x["flows"] += _num(r.get("flows"))
        x["ips"] += ips


def tcp_query(log_format: str) -> str | None:
    """TCP connections that failed although nothing refused them, from the tcp-flags field (flow-log format
    v3 or later; None without it). Flow logs record only FIN, SYN, RST and SYN-ACK, so:

    * unanswered: an initiator's record with SYN alone and 3 or more packets, i.e. the SYN was sent again and
      again with no reply (a timeout). One that was answered has data or a FIN in the same window, so is left
      out; a single SYN is left out too, since its reply may fall in the next window;
    * reset: RST with no SYN-ACK in 1 or 2 packets: refused by the host (no one listening on the port) or cut.

    Zero windows, retransmissions and the like are not in flow logs: only a packet capture shows them."""
    fields = [f.strip("${}").replace("-", "_") for f in (log_format or DEFAULT_FORMAT).split()]
    if not set(_NEEDED) | {"tcp_flags", "packets", "protocol"} <= set(fields):
        return None
    src = "pkt_srcaddr" if "pkt_srcaddr" in fields else "srcaddr"
    dst = "pkt_dstaddr" if "pkt_dstaddr" in fields else "dstaddr"
    names = [f"f_{f}" for f in fields]
    return (
        f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join(names)}'
        f' | filter f_action = "ACCEPT" and f_protocol = "6" and f_{src} != "-"'
        ' and ((f_tcp_flags = "2" and f_packets >= 3) or (f_tcp_flags = "4" and f_packets <= 2))'
        f" | stats sum(f_bytes) as bytes, sum(f_packets) as packets, count(*) as flows"
        f" by f_{src} as src, f_{dst} as dst, f_dstport as port, f_tcp_flags as flags"
        f" | sort flows desc | limit {FLOW_ROWS}"
    )


def baseline_query(log_format: str) -> str | None:
    """Every source and target that failed (refused, or by tcp_query's rules) over the days before the day
    read: what is new today is what is not in this list."""
    fields = [f.strip("${}").replace("-", "_") for f in (log_format or DEFAULT_FORMAT).split()]
    if not set(_NEEDED) <= set(fields):
        return None
    src = "pkt_srcaddr" if "pkt_srcaddr" in fields else "srcaddr"
    dst = "pkt_dstaddr" if "pkt_dstaddr" in fields else "dstaddr"
    names = [f"f_{f}" for f in fields]
    failed = 'f_action = "REJECT"'
    if {"tcp_flags", "packets", "protocol"} <= set(fields):
        failed = (f'({failed} or (f_action = "ACCEPT" and f_protocol = "6" and ((f_tcp_flags = "2" and '
                  'f_packets >= 3) or (f_tcp_flags = "4" and f_packets <= 2))))')  # fmt: skip
    return (
        f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join(names)}'
        f' | filter {failed} and f_{src} != "-"'
        f" | stats count(*) as flows by f_{src} as src, f_{dst} as dst | limit {BASE_ROWS}"
    )


BASE_DAYS = 7  # failed traffic today is compared with the days before it, to show what is new
BASE_ROWS = 10000  # Insights' most rows: a baseline that fills it is too large to say what is new
BASE_WAIT = 300


def _insights(logs, groups: list[str], query: str, start: int, end: int, stats: dict | None = None,
              wait: float = FLOW_WAIT, limit: int = FLOW_ROWS) -> list[dict] | None:  # fmt: skip
    """Rows of one Logs Insights query, None when it failed or ran too long. ``stats`` adds up the bytes
    Insights scanned (what the query is billed on)."""
    import time as _time

    qid = logs.start_query(logGroupNames=groups[:50], startTime=start, endTime=end, queryString=query,
                           limit=limit)["queryId"]  # fmt: skip
    waited = 0.0
    while waited < wait:
        res = logs.get_query_results(queryId=qid)
        status = res.get("status")
        if status in ("Complete", "Failed", "Cancelled", "Timeout") and stats is not None:
            stats["bytes"] = stats.get("bytes", 0) + int(float((res.get("statistics") or {}).get("bytesScanned") or 0))
        if status == "Complete":
            return [{c["field"]: c.get("value") for c in row} for row in res.get("results") or []]
        if status in ("Failed", "Cancelled", "Timeout"):
            return None
        _time.sleep(1.0)
        waited += 1.0
    try:
        logs.stop_query(queryId=qid)
    except Exception as exc:  # noqa: BLE001 - stopping is best effort; the query ends on its own
        log.debug("could not stop flow-log query %s: %s", qid, exc)
    return None


def task_access_flows(ctx, region: str) -> None:
    if not getattr(ctx, "flows", False):
        return
    try:
        _access_flows(ctx, region)
    except ClientError as exc:
        code, msg, _ = describe_exception(exc)
        if failure_kind(code, msg) != "permission":
            raise
        # Refused (ec2:DescribeFlowLogs or logs:StartQuery): recorded, so the region reads "denied", never 0.
        ctx.r.fact("access_flows", {"hours": FLOW_HOURS, "refused": code, "rows": [], "covered": [], "s3_only": [],
                                    "unreadable": [], "rejected": [], "reject_covered": []}, region)  # fmt: skip
        raise


def _access_flows(ctx, region: str) -> None:
    ec2 = ctx.client("ec2", region)
    out: dict = {"hours": FLOW_HOURS, "rows": [], "covered": [], "s3_only": [], "unreadable": [],
                 "rejected": [], "reject_covered": []}  # fmt: skip
    by_format: dict[str, dict] = {}
    rejects: dict[str, dict] = {}  # flow logs that record refused traffic (ALL or REJECT)
    scanned: dict = {}  # bytes Insights scanned, for the cost
    for f in _pages(ec2, "describe_flow_logs", "FlowLogs"):
        if f.get("FlowLogStatus") != "ACTIVE":
            continue
        if (
            f.get("TrafficType") in ("ALL", "REJECT")
            and f.get("LogGroupName")
            and f.get("LogDestinationType", "cloud-watch-logs") == "cloud-watch-logs"
        ):
            g = rejects.setdefault(f.get("LogFormat") or DEFAULT_FORMAT, {"groups": set(), "resources": set()})
            g["groups"].add(f["LogGroupName"])
            g["resources"].add(f.get("ResourceId", ""))
        if f.get("TrafficType") == "REJECT":
            continue
        rid = f.get("ResourceId", "")
        if f.get("LogDestinationType", "cloud-watch-logs") != "cloud-watch-logs" or not f.get("LogGroupName"):
            out["s3_only"].append(rid)
            continue
        g = by_format.setdefault(f.get("LogFormat") or DEFAULT_FORMAT, {"groups": set(), "resources": set()})
        g["groups"].add(f["LogGroupName"])
        g["resources"].add(rid)
    end = int(ctx.now.timestamp())
    start = end - FLOW_HOURS * 3600
    logs = ctx.client("logs", region)
    totals = {}
    for fmt, g in list(by_format.items())[:3]:
        query = flow_query(fmt)
        if not query:
            out["unreadable"] += sorted(g["resources"])
            continue
        rows = with_backoff(lambda q=query, g=g: _insights(logs, sorted(g["groups"]), q, start, end, scanned))
        if rows is None:
            out["unreadable"] += sorted(g["resources"])
            continue
        out["covered"] += sorted(g["resources"])
        for r in rows:
            try:
                b, n = int(float(r.get("bytes") or 0)), int(float(r.get("flows") or 0))
            except ValueError:
                continue
            out["rows"].append({"src": r.get("src"), "dst": r.get("dst"), "port": r.get("port"), "bytes": b,
                                "flows": n})  # fmt: skip
        total_q = internet_query(fmt) or query.split(" | stats")[0] + " | stats sum(f_bytes) as bytes"
        total = with_backoff(lambda q=total_q, g=g: _insights(logs, sorted(g["groups"]), q, start, end, scanned))
        if total:
            totals[fmt] = sum(_num(t.get("bytes")) for t in total)
            _add_internet(out, total)
    # Refused traffic: what security groups and network ACLs turned away, by source, target and port.
    for fmt, g in list(rejects.items())[:3]:
        query = flow_query(fmt, "REJECT")
        rows = (
            with_backoff(lambda q=query, g=g: _insights(logs, sorted(g["groups"]), q, start, end, scanned))
            if query
            else None
        )
        if rows is None:
            continue
        out["reject_covered"] += sorted(g["resources"])
        for r in rows:
            try:
                b, n = int(float(r.get("bytes") or 0)), int(float(r.get("flows") or 0))
            except ValueError:
                continue
            out["rejected"].append({"src": r.get("src"), "dst": r.get("dst"), "port": r.get("port"), "bytes": b,
                                    "flows": n})  # fmt: skip
    _failed_tcp(out, rejects, logs, start, end, scanned)
    _new_today(out, rejects, logs, start, scanned)
    out["insights_bytes"] = scanned.get("bytes", 0)
    out["rejected"] = sorted(out["rejected"], key=lambda r: -r["flows"])[:FLOW_ROWS]
    out["rows"] = sorted(out["rows"], key=lambda r: -r["bytes"])[:FLOW_ROWS]
    out["total_bytes"] = sum(totals.values()) or sum(r["bytes"] for r in out["rows"])
    ctx.r.fact("access_flows", out, region)


def _num(v) -> int:
    try:
        return int(float(v or 0))
    except (TypeError, ValueError):
        return 0


def _failed_tcp(out: dict, rejects: dict, logs, start: int, end: int, scanned: dict) -> None:
    """``out["failed_tcp"]``: connections nobody answered, and connections reset, by tcp_query."""
    out["failed_tcp"], out["tcp_covered"] = [], []
    for fmt, g in list(rejects.items())[:3]:
        query = tcp_query(fmt)
        if not query:
            continue
        rows = with_backoff(lambda q=query, g=g: _insights(logs, sorted(g["groups"]), q, start, end, scanned))
        if rows is None:
            continue
        out["tcp_covered"] += sorted(g["resources"])
        for r in rows:
            if not r.get("src") or not r.get("dst"):
                continue
            kind = "unanswered" if str(r.get("flags")) == "2" else "reset"
            out["failed_tcp"].append({"src": r["src"], "dst": r["dst"], "port": r.get("port"), "kind": kind,
                                      "flows": _num(r.get("flows")), "packets": _num(r.get("packets")),
                                      "bytes": _num(r.get("bytes"))})  # fmt: skip
    out["failed_tcp"] = sorted(out["failed_tcp"], key=lambda r: -r["flows"])[:FLOW_ROWS]


def _new_today(out: dict, rejects: dict, logs, start: int, scanned: dict) -> None:
    """Mark each failed row today ``new`` (this source and target never failed in the BASE_DAYS before) and
    ``src_new`` (this source never failed at all). A baseline that fills BASE_ROWS, or a query that fails,
    marks nothing: an unread baseline must not make everything look new."""
    pairs: set[tuple] = set()
    read = full = False
    for fmt, g in list(rejects.items())[:3]:
        query = baseline_query(fmt)
        if not query:
            continue
        rows = with_backoff(lambda q=query, g=g: _insights(logs, sorted(g["groups"]), q, start - BASE_DAYS * 86400,
                                                           start, scanned, BASE_WAIT, BASE_ROWS))  # fmt: skip
        if rows is None:
            out["baseline"] = {"days": BASE_DAYS, "read": False}
            return
        read = True
        full = full or len(rows) >= BASE_ROWS
        pairs.update((r.get("src"), r.get("dst")) for r in rows)
    out["baseline"] = {"days": BASE_DAYS, "read": read and not full, "full": full, "pairs": len(pairs)}
    if not read or full:
        return
    sources = {s for s, _ in pairs}
    for r in (*out["rejected"], *out["failed_tcp"]):
        r["new"] = (r["src"], r["dst"]) not in pairs
        r["src_new"] = r["src"] not in sources


# ---------------------------------------------------------------- failed and blocked traffic
#
# ``facts.access_failures[region]``: what was refused, blocked, dropped or failed at the account's edge in the
# last FAIL_HOURS, read from CloudWatch metrics (one GetMetricData round per region, SEARCH expressions, cheap,
# always on with Cloud Assurance). Flow logs carry only ACCEPT or REJECT, never HTTP codes; the codes come from
# the load balancers, API Gateway and WAF. Most of these metrics are published only when non-zero, so a family
# with resources and no data points read is a true 0. ``present`` counts each family's resources from a metric
# that is always published, so the report can tell "0 across 12" from "none here".

FAIL_HOURS = 24
FAIL_TOP = 10
# key: (family, namespace, dimensions, metric, statistic, extra filter)
FAIL_METRICS: dict[str, tuple] = {
    "alb_elb_4xx": ("alb", "AWS/ApplicationELB", ("LoadBalancer",), "HTTPCode_ELB_4XX_Count", "Sum", ""),
    "alb_elb_5xx": ("alb", "AWS/ApplicationELB", ("LoadBalancer",), "HTTPCode_ELB_5XX_Count", "Sum", ""),
    "alb_target_5xx": ("alb", "AWS/ApplicationELB", ("LoadBalancer",), "HTTPCode_Target_5XX_Count", "Sum", ""),
    "alb_rejected": ("alb", "AWS/ApplicationELB", ("LoadBalancer",), "RejectedConnectionCount", "Sum", ""),
    "alb_tls": ("alb", "AWS/ApplicationELB", ("LoadBalancer",), "ClientTLSNegotiationErrorCount", "Sum", ""),
    **{
        f"nlb_sg_{d}_{p.lower()}": ("nlb", "AWS/NetworkELB", ("LoadBalancer",),
                                    f"SecurityGroupBlockedFlowCount_{d.title()}bound_{p}", "Sum", "")
        for d in ("in", "out") for p in ("TCP", "UDP", "ICMP")
    },
    "nlb_elb_reset": ("nlb", "AWS/NetworkELB", ("LoadBalancer",), "TCP_ELB_Reset_Count", "Sum", ""),
    "nlb_target_reset": ("nlb", "AWS/NetworkELB", ("LoadBalancer",), "TCP_Target_Reset_Count", "Sum", ""),
    "nlb_tls": ("nlb", "AWS/NetworkELB", ("LoadBalancer",), "ClientTLSNegotiationErrorCount", "Sum", ""),
    "waf_blocked": ("waf", "AWS/WAFV2", ("Region", "Rule", "WebACL"), "BlockedRequests", "Sum", 'Rule="ALL"'),
    "nfw_dropped": ("nfw", "AWS/NetworkFirewall", ("AvailabilityZone", "Engine", "FirewallName"), "DroppedPackets",
                    "Sum", ""),
    "nat_port": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ErrorPortAllocation", "Sum", ""),
    "nat_attempts": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ConnectionAttemptCount", "Sum", ""),
    "nat_established": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ConnectionEstablishedCount", "Sum", ""),
    "alb_target_conn": ("alb", "AWS/ApplicationELB", ("LoadBalancer",), "TargetConnectionErrorCount", "Sum", ""),
    "nat_drop": ("nat", "AWS/NATGateway", ("NatGatewayId",), "PacketsDropCount", "Sum", ""),
    "tgw_blackhole": ("tgw", "AWS/TransitGateway", ("TransitGateway",), "PacketDropCountBlackhole", "Sum", ""),
    "tgw_noroute": ("tgw", "AWS/TransitGateway", ("TransitGateway",), "PacketDropCountNoRoute", "Sum", ""),
    "api_rest_4xx": ("api_rest", "AWS/ApiGateway", ("ApiName",), "4XXError", "Sum", ""),
    "api_rest_5xx": ("api_rest", "AWS/ApiGateway", ("ApiName",), "5XXError", "Sum", ""),
    "api_http_4xx": ("api_http", "AWS/ApiGateway", ("ApiId",), "4xx", "Sum", ""),
    "api_http_5xx": ("api_http", "AWS/ApiGateway", ("ApiId",), "5xx", "Sum", ""),
    "vpce_dropped": ("vpce", "AWS/PrivateLinkEndpoints", ("Endpoint Type", "Service Name", "VPC Endpoint Id", "VPC Id"),
                     "PacketsDropped", "Sum", ""),
    "vpcs_rst": ("vpcs", "AWS/PrivateLinkServices", ("Service Id",), "RstPacketsSent", "Sum", ""),
    "db_login": ("aurora_mysql", "AWS/RDS", ("DBInstanceIdentifier",), "LoginFailures", "Average", ""),
}  # fmt: skip
# Each family's always-published metric, to count its resources: (namespace, dimensions, metric, filter).
FAIL_PRESENT: dict[str, tuple] = {
    "alb": ("AWS/ApplicationELB", ("LoadBalancer",), "ConsumedLCUs", ""),
    "nlb": ("AWS/NetworkELB", ("LoadBalancer",), "ConsumedLCUs", ""),
    "waf": ("AWS/WAFV2", ("Region", "Rule", "WebACL"), "AllowedRequests", 'Rule="ALL"'),
    "nfw": ("AWS/NetworkFirewall", ("AvailabilityZone", "FirewallName"), "ReceivedPackets", ""),
    "nat": ("AWS/NATGateway", ("NatGatewayId",), "ActiveConnectionCount", ""),
    "tgw": ("AWS/TransitGateway", ("TransitGateway",), "BytesIn", ""),
    "api_rest": ("AWS/ApiGateway", ("ApiName",), "Count", ""),
    "api_http": ("AWS/ApiGateway", ("ApiId",), "Count", ""),
    "vpce": ("AWS/PrivateLinkEndpoints", ("Endpoint Type", "Service Name", "VPC Endpoint Id", "VPC Id"),
             "BytesProcessed", ""),
    "vpcs": ("AWS/PrivateLinkServices", ("Service Id",), "EndpointsCount", ""),
    "aurora_mysql": ("AWS/RDS", ("DBInstanceIdentifier",), "LoginFailures", ""),
}  # fmt: skip
# The dimension that names the resource in each family (the report's "where").
FAIL_NAME = {"alb": "LoadBalancer", "nlb": "LoadBalancer", "waf": "WebACL", "nfw": "FirewallName",
             "nat": "NatGatewayId", "tgw": "TransitGateway", "api_rest": "ApiName", "api_http": "ApiId",
             "vpce": "VPC Endpoint Id", "vpcs": "Service Id", "aurora_mysql": "DBInstanceIdentifier"}  # fmt: skip


def _fail_search(ns: str, dims: tuple, metric: str, stat: str, extra: str, period: int) -> str:
    from .healthcheck import _dim

    schema = ",".join([ns, *(_dim(d) for d in dims)])
    filt = f" {extra}" if extra else ""
    return f"SEARCH('{{{schema}}} MetricName=\"{metric}\"{filt}', '{stat}', {period})"


def failure_queries(region: str, period: int = 3600) -> list[dict]:
    """The GetMetricData queries for one region: every failure metric, then each family's presence metric.
    WAF web ACLs for CloudFront report in us-east-1 without the Region dimension, so that region asks for them
    too."""
    q = []
    metrics = dict(FAIL_METRICS)
    present = dict(FAIL_PRESENT)
    if region == "us-east-1":
        metrics["waf_blocked_cf"] = ("waf_cf", "AWS/WAFV2", ("Rule", "WebACL"), "BlockedRequests", "Sum", 'Rule="ALL"')
        present["waf_cf"] = ("AWS/WAFV2", ("Rule", "WebACL"), "AllowedRequests", 'Rule="ALL"')
    for i, (key, (fam, ns, dims, metric, stat, extra)) in enumerate(metrics.items()):
        name = FAIL_NAME.get(fam, "WebACL")
        q.append({"Id": f"f{i}", "Expression": _fail_search(ns, dims, metric, stat, extra, period),
                  "Label": f"${{PROP('Dim.{name}')}}", "ReturnData": True, "_key": key, "_stat": stat})  # fmt: skip
    for i, (fam, (ns, dims, metric, extra)) in enumerate(present.items()):
        name = FAIL_NAME.get(fam, "WebACL")
        q.append({"Id": f"p{i}", "Expression": _fail_search(ns, dims, metric, "SampleCount", extra, period),
                  "Label": f"${{PROP('Dim.{name}')}}", "ReturnData": True, "_present": fam})  # fmt: skip
    return q


def failure_totals(queries: list[dict], data: dict, period: int = 3600) -> tuple[dict, dict]:
    """(metrics, present) from GetMetricData results: metrics {key: {"total", "top": [[name, value]]}} with
    every key present (0 when nothing was published), present {family: resources seen}. An Average metric
    (LoginFailures is failures per second) is turned into a count by the period's seconds."""
    metrics: dict[str, dict] = {}
    present: dict[str, int] = {}
    raw: dict[str, dict] = {}
    for q in queries:
        series = data.get(q["Id"]) or {}
        if "_present" in q:
            fam = q["_present"]
            present[fam] = present.get(fam, 0) + len(series)
            continue
        scale = period if q["_stat"] == "Average" else 1
        by = {name: round(sum(v for _, v in pts) * scale) for name, pts in series.items()}
        by = {k: v for k, v in by.items() if v > 0}
        raw[q["_key"]] = by
        top = sorted(by.items(), key=lambda kv: -kv[1])[:FAIL_TOP]
        metrics[q["_key"]] = {"total": sum(by.values()), "top": [[k, v] for k, v in top], "resources": len(by)}
    # NAT connections attempted and never established: outbound connections nobody answered.
    tried, made = raw.pop("nat_attempts", {}), raw.pop("nat_established", {})
    metrics.pop("nat_attempts", None), metrics.pop("nat_established", None)
    if "nat_attempts" in {q.get("_key") for q in queries}:
        by = {k: v - made.get(k, 0) for k, v in tried.items() if v - made.get(k, 0) > 0}
        top = sorted(by.items(), key=lambda kv: -kv[1])[:FAIL_TOP]
        metrics["nat_unanswered"] = {"total": sum(by.values()), "top": [[k, v] for k, v in top], "resources": len(by)}
    return metrics, present


def task_access_failures(ctx, region: str) -> None:
    from datetime import timedelta

    from .healthcheck import _metric_data

    period = 3600
    end = ctx.now.replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=FAIL_HOURS)
    queries = failure_queries(region, period)
    lq = link_queries(period)
    out: dict = {"hours": FAIL_HOURS}
    cut: list = []
    cw = ctx.client("cloudwatch", region)
    sent = [{k: v for k, v in q.items() if not k.startswith("_")} for q in (*queries, *lq)]
    data = _soft(out, "CloudWatch metrics", lambda: _metric_data(cw, sent, start, end, cut))
    if data is None:
        ctx.r.fact("access_failures", out, region)
        return
    out["metrics"], out["present"] = failure_totals(queries, data, period)
    out["links"] = link_totals(lq, data)
    if cut:
        out["cut"] = sorted({q.get("_key") or q.get("_present") for q in (*queries, *lq) if q["Id"] in cut})
    if "dx" in out.get("links", {}):
        dx = _soft(out, "Direct Connect connections", lambda: _dx_connections(ctx, region))
        if dx is not None:
            out["dx"] = dx
    ctx.r.fact("access_failures", out, region)


# ---------------------------------------------------------------- the links: TGW, DX, VPN, NAT, PrivateLink
#
# ``facts.access_failures[region]["links"]``: how each transit gateway (and each attachment), Direct Connect
# connection and virtual interface, VPN tunnel, NAT gateway and PrivateLink endpoint or service carried traffic
# and failed in the last FAIL_HOURS: {family: {resource label: {metric: {sum, max, min, hours?}}}}. CloudWatch
# metrics only (GetMetricData SEARCH, already in the role); Direct Connect connections are named from
# DescribeConnections, which the assurance checks read too.

_PL_EP = ("Endpoint Type", "Service Name", "VPC Endpoint Id", "VPC Id")
# key: (family, namespace, dimensions, metric, statistic)
LINK_METRICS: dict[str, tuple] = {
    "tgw_in": ("tgw", "AWS/TransitGateway", ("TransitGateway",), "BytesIn", "Sum"),
    "tgw_out": ("tgw", "AWS/TransitGateway", ("TransitGateway",), "BytesOut", "Sum"),
    "tgw_hole": ("tgw", "AWS/TransitGateway", ("TransitGateway",), "PacketDropCountBlackhole", "Sum"),
    "tgw_noroute": ("tgw", "AWS/TransitGateway", ("TransitGateway",), "PacketDropCountNoRoute", "Sum"),
    "tgwa_in": ("tgwa", "AWS/TransitGateway", ("TransitGateway", "TransitGatewayAttachment"), "BytesIn", "Sum"),
    "tgwa_out": ("tgwa", "AWS/TransitGateway", ("TransitGateway", "TransitGatewayAttachment"), "BytesOut", "Sum"),
    "tgwa_hole": ("tgwa", "AWS/TransitGateway", ("TransitGateway", "TransitGatewayAttachment"),
                  "PacketDropCountBlackhole", "Sum"),
    "tgwa_noroute": ("tgwa", "AWS/TransitGateway", ("TransitGateway", "TransitGatewayAttachment"),
                     "PacketDropCountNoRoute", "Sum"),
    "dx_state": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionState", "Minimum"),
    "dx_in_max": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionBpsIngress", "Maximum"),
    "dx_out_max": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionBpsEgress", "Maximum"),
    "dx_in": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionBpsIngress", "Average"),
    "dx_out": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionBpsEgress", "Average"),
    "dx_err": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionErrorCount", "Sum"),
    "dx_crc": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionCRCErrorCount", "Sum"),
    "dx_light": ("dx", "AWS/DX", ("ConnectionId",), "ConnectionLightLevelRx", "Minimum"),
    "vif_in": ("vif", "AWS/DX", ("ConnectionId", "VirtualInterfaceId"), "VirtualInterfaceBpsIngress", "Maximum"),
    "vif_out": ("vif", "AWS/DX", ("ConnectionId", "VirtualInterfaceId"), "VirtualInterfaceBpsEgress", "Maximum"),
    "vpn_state": ("vpn", "AWS/VPN", ("VpnId", "TunnelIpAddress"), "TunnelState", "Minimum"),
    "vpn_in": ("vpn", "AWS/VPN", ("VpnId", "TunnelIpAddress"), "TunnelDataIn", "Sum"),
    "vpn_out": ("vpn", "AWS/VPN", ("VpnId", "TunnelIpAddress"), "TunnelDataOut", "Sum"),
    "nat_try": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ConnectionAttemptCount", "Sum"),
    "nat_made": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ConnectionEstablishedCount", "Sum"),
    "nat_port": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ErrorPortAllocation", "Sum"),
    "nat_drop": ("nat", "AWS/NATGateway", ("NatGatewayId",), "PacketsDropCount", "Sum"),
    "nat_idle": ("nat", "AWS/NATGateway", ("NatGatewayId",), "IdleTimeoutCount", "Sum"),
    "nat_active": ("nat", "AWS/NATGateway", ("NatGatewayId",), "ActiveConnectionCount", "Maximum"),
    "nat_out": ("nat", "AWS/NATGateway", ("NatGatewayId",), "BytesOutToDestination", "Sum"),
    "nat_in": ("nat", "AWS/NATGateway", ("NatGatewayId",), "BytesInFromDestination", "Sum"),
    "vpce_bytes": ("vpce", "AWS/PrivateLinkEndpoints", _PL_EP, "BytesProcessed", "Sum"),
    "vpce_new": ("vpce", "AWS/PrivateLinkEndpoints", _PL_EP, "NewConnections", "Sum"),
    "vpce_drop": ("vpce", "AWS/PrivateLinkEndpoints", _PL_EP, "PacketsDropped", "Sum"),
    "vpce_rst": ("vpce", "AWS/PrivateLinkEndpoints", _PL_EP, "RstPacketsReceived", "Sum"),
    "vpcs_bytes": ("vpcs", "AWS/PrivateLinkServices", ("Service Id",), "BytesProcessed", "Sum"),
    "vpcs_new": ("vpcs", "AWS/PrivateLinkServices", ("Service Id",), "NewConnections", "Sum"),
    "vpcs_rst": ("vpcs", "AWS/PrivateLinkServices", ("Service Id",), "RstPacketsSent", "Sum"),
    "vpcs_eps": ("vpcs", "AWS/PrivateLinkServices", ("Service Id",), "EndpointsCount", "Maximum"),
    "vpcse_bytes": ("vpcse", "AWS/PrivateLinkServices", ("Service Id", "VPC Endpoint Id"), "BytesProcessed", "Sum"),
    "vpcse_rst": ("vpcse", "AWS/PrivateLinkServices", ("Service Id", "VPC Endpoint Id"), "RstPacketsSent", "Sum"),
}  # fmt: skip
# The label of each family's series: its dimensions, joined by "|".
LINK_LABEL = {"tgw": ("TransitGateway",), "tgwa": ("TransitGateway", "TransitGatewayAttachment"),
              "dx": ("ConnectionId",), "vif": ("ConnectionId", "VirtualInterfaceId"),
              "vpn": ("VpnId", "TunnelIpAddress"), "nat": ("NatGatewayId",),
              "vpce": ("VPC Endpoint Id", "Service Name", "VPC Id"), "vpcs": ("Service Id",),
              "vpcse": ("Service Id", "VPC Endpoint Id")}  # fmt: skip
# Kept hour by hour (FAIL_HOURS values), for the shape of the day.
LINK_HOURS = {"tgw_in", "tgw_out", "dx_in", "dx_out", "dx_state", "vpn_state", "nat_try", "nat_made", "tgwa_in",
              "tgwa_out"}  # fmt: skip


def link_queries(period: int = 3600) -> list[dict]:
    q = []
    for i, (key, (fam, ns, dims, metric, stat)) in enumerate(LINK_METRICS.items()):
        label = "|".join(f"${{PROP('Dim.{d}')}}" for d in LINK_LABEL[fam])
        q.append({"Id": f"l{i}", "Expression": _fail_search(ns, dims, metric, stat, "", period), "Label": label,
                  "ReturnData": True, "_key": key, "_fam": fam, "_stat": stat})  # fmt: skip
    return q


def link_totals(queries: list[dict], data: dict) -> dict:
    """{family: {label: {key: {sum, max, min, hours?}}}} from GetMetricData results."""
    out: dict[str, dict] = {}
    for q in queries:
        for label, pts in (data.get(q["Id"]) or {}).items():
            vals = [float(v) for _, v in pts]
            if not vals:
                continue
            x = {"sum": round(sum(vals), 2), "max": round(max(vals), 2), "min": round(min(vals), 2), "n": len(vals)}
            if q["_key"] in LINK_HOURS:
                x["hours"] = [[t.isoformat() if hasattr(t, "isoformat") else str(t), round(float(v), 2)]
                              for t, v in pts]  # fmt: skip
            out.setdefault(q["_fam"], {}).setdefault(label, {})[q["_key"]] = x
    return out


def _dx_connections(ctx, region: str) -> list[dict]:
    conns = ctx.client("directconnect", region).describe_connections().get("connections") or []
    return [{"id": c.get("connectionId"), "name": c.get("connectionName", ""), "location": c.get("location", ""),
             "bandwidth": c.get("bandwidth", ""), "state": c.get("connectionState", ""),
             "partner": c.get("partnerName", ""), "lag": c.get("lagId", ""), "vlan": c.get("vlan"),
             "has_logical_redundancy": c.get("hasLogicalRedundancy", "")} for c in conns]  # fmt: skip


# ---------------------------------------------------------------- refused API calls (CloudTrail)
#
# ``facts.trail_denials``: API calls AWS refused in the last FAIL_HOURS (access denied, unauthorised, failed
# console sign-ins), read with Logs Insights from trails that deliver to a CloudWatch Logs group in this
# account. An organisation trail read in the management account covers every account, so rows carry the
# account the call was made against. Billed per GB scanned like the flow logs, so read only when the scan
# asks for flow logs.

DENIAL_ROWS = 1000
DENIAL_CODES = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Client.UnauthorizedOperation",
                "UnauthorizedAccess", "NotAuthorized", "Forbidden", "InvalidClientTokenId",
                "SignatureDoesNotMatch")  # fmt: skip


def denial_query() -> str:
    codes = "|".join(DENIAL_CODES).replace(".", "\\.")
    return (
        f'filter errorCode like /{codes}/ or (eventName = "ConsoleLogin" and errorMessage like /Failed/)'
        " | fields recipientAccountId, sourceIPAddress, eventSource, eventName, errorCode,"
        " coalesce(userIdentity.arn, userIdentity.principalId, userIdentity.type) as who"
        " | stats count(*) as n by recipientAccountId as account, who, sourceIPAddress as ip, eventSource as svc,"
        " eventName as call, errorCode as code"
        f" | sort n desc | limit {DENIAL_ROWS}"
    )


def task_trail_denials(ctx) -> None:
    if not getattr(ctx, "flows", False):
        return
    ct = ctx.client("cloudtrail", ctx.home)
    out: dict = {"hours": FAIL_HOURS, "rows": [], "trails": [], "totals": {}}
    trails = _soft(out, "trails", lambda: with_backoff(ct.describe_trails, includeShadowTrails=True)) or {}
    groups: dict[str, dict] = {}  # region -> {groups, org}
    for t in trails.get("trailList") or []:
        arn = t.get("CloudWatchLogsLogGroupArn") or ""
        parts = arn.split(":")
        if len(parts) < 7 or parts[4] != ctx.account_id:
            continue
        g = groups.setdefault(parts[3], {"groups": set(), "org": False})
        g["groups"].add(parts[6])
        g["org"] = g["org"] or bool(t.get("IsOrganizationTrail"))
        out["trails"].append({"name": t.get("Name"), "org": bool(t.get("IsOrganizationTrail")), "group": parts[6],
                              "region": parts[3]})  # fmt: skip
    if not groups:
        ctx.r.fact("trail_denials", out)
        return
    end = int(ctx.now.timestamp())
    start = end - FAIL_HOURS * 3600
    seen: dict[tuple, int] = {}
    read_any = False
    for region, g in groups.items():
        logs = ctx.client("logs", region)
        rows = _soft(out, f"CloudTrail logs in {region}",
                     lambda g=g, logs=logs: with_backoff(lambda: _insights(logs, sorted(g["groups"]), denial_query(),
                                                                           start, end)))  # fmt: skip
        totals = _soft(out, f"CloudTrail totals in {region}",
                       lambda g=g, logs=logs: with_backoff(lambda: _insights(
                           logs, sorted(g["groups"]), denial_query().split(" | fields")[0]
                           + " | stats count(*) as n by recipientAccountId as account", start, end)))  # fmt: skip
        if rows is None:
            continue
        read_any = True
        for r in rows:
            try:
                n = int(float(r.get("n") or 0))
            except ValueError:
                continue
            key = tuple(r.get(k) or "" for k in ("account", "who", "ip", "svc", "call", "code"))
            seen[key] = seen.get(key, 0) + n
        for r in totals or []:
            try:
                out["totals"][r.get("account") or ""] = out["totals"].get(r.get("account") or "", 0) + int(
                    float(r.get("n") or 0)
                )
            except ValueError:
                continue
    out["read"] = read_any
    out["org"] = any(g["org"] for g in groups.values())
    out["rows"] = [{"account": k[0], "who": k[1], "ip": k[2], "svc": k[3], "call": k[4], "code": k[5], "n": n}
                   for k, n in sorted(seen.items(), key=lambda kv: -kv[1])][:DENIAL_ROWS]  # fmt: skip
    ctx.r.fact("trail_denials", out)
