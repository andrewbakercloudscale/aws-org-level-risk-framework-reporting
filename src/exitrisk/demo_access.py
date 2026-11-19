"""Synthetic Access Graph facts for the demo organisation (screenshots and tests).

Added to the demo's Cloud Assurance facts: a production transit gateway owned by the network account
outside the scan and a non-production one, two VPC peerings, a PrivateLink service, security groups
that admit other accounts (one of them the classic 10.0.0.0/8 rule), and role and bucket trusts:
the audit account into every account, a vendor with an external id, a GitHub OIDC deploy role, a role
that trusts anyone. Deterministic for a given seed.
"""

from __future__ import annotations

import random

from .demo_outage import NETWORK_ACCOUNT

VENDOR = "444455556666"  # a monitoring vendor, outside the organisation
PARTNER = "777788889999"  # a payments partner, outside the organisation
REGION = "eu-west-1"
GITHUB = "arn:aws:iam::{acct}:oidc-provider/token.actions.githubusercontent.com"


def _empty(cidr: str) -> dict:
    return {"cidrs": [cidr], "peerings": [], "tgw_attachments": [], "services": [], "endpoints": [],
            "sg_refs": [], "sg_cidrs": []}  # fmt: skip


def add_facts(assurance: dict, accounts: list[dict], seed: int = 13) -> dict:
    """Add access_network and access_trusts facts to ``assurance['accounts']`` in place; returns it."""
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data
    checked = assurance.get("accounts") or {}
    by_name = {a["name"]: a["id"] for a in accounts if a["id"] in checked}
    ids = list(checked)
    if not ids:
        return assurance

    def acct(part: str) -> str | None:
        return next((i for n, i in by_name.items() if part in n), None)

    net = {aid: _empty(f"10.{(i * 7) % 250}.0.0/16") for i, aid in enumerate(ids)}
    trusts: dict[str, list[dict]] = {aid: [] for aid in ids}
    hub_np = acct("shared-network")

    for aid in ids:
        name = next(n for n, i in by_name.items() if i == aid)
        prod = name.endswith("-prod")
        if prod and rng.random() < 0.8 or "shared-network" in name:
            net[aid]["tgw_attachments"].append({"id": f"tgw-attach-{aid[-6:]}", "tgw": "tgw-0demo",
                                                "tgw_owner": NETWORK_ACCOUNT, "owner": aid, "type": "vpc",
                                                "resource": f"vpc-{aid[-8:]}"})  # fmt: skip
        elif not prod and hub_np and rng.random() < 0.7:
            net[aid]["tgw_attachments"].append({"id": f"tgw-attach-np-{aid[-6:]}", "tgw": "tgw-0nonprod",
                                                "tgw_owner": hub_np, "owner": aid, "type": "vpc",
                                                "resource": f"vpc-{aid[-8:]}"})  # fmt: skip
        audit = acct("security-audit")
        if audit and audit != aid:
            trusts[aid].append({"role": "SecurityAuditRole", "kind": "account", "id": audit, "external_id": False})
        ident = acct("identity-prod")
        if ident and ident != aid and rng.random() < 0.3:
            trusts[aid].append({"role": "BreakGlassAdmin", "kind": "account", "id": ident, "external_id": False})

    def peer(a: str | None, b: str | None, pid: str) -> None:
        if a and b:
            p = {"id": pid, "requester": a, "requester_region": REGION, "requester_cidrs": net[a]["cidrs"],
                 "accepter": b, "accepter_region": REGION, "accepter_cidrs": net[b]["cidrs"]}  # fmt: skip
            net[a]["peerings"].append(p)
            net[b]["peerings"].append(p)

    peer(acct("data-platform-prod"), acct("fraud-analytics"), "pcx-0demo1")
    peer(acct("legacy-batch"), acct("core-banking"), "pcx-0demo2")

    pay, cards, partner_api = acct("payments-core-prod"), acct("cards-processing-prod"), acct("partner-api")
    if pay:
        svc = "com.amazonaws.vpce.eu-west-1.vpce-svc-0pay0demo"
        allowed = [f"arn:aws:iam::{a}:root" for a in (cards, PARTNER) if a]
        net[pay]["services"].append({"id": "vpce-svc-0pay0demo", "name": svc, "acceptance": True, "allowed": allowed})
        net[pay]["sg_cidrs"].append({"cidr": "10.0.0.0/8", "ports": "tcp 5432", "groups": ["sg-0paydb0demo"]})
        net[pay]["sg_cidrs"].append({"cidr": "172.16.20.0/24", "ports": "tcp 443", "groups": ["sg-0payapi0demo"]})
        if cards:
            net[cards]["endpoints"].append({"id": "vpce-0cards0demo", "service": svc})
    if partner_api:
        name = "com.amazonaws.vpce.eu-west-1.vpce-svc-0partner"
        net[partner_api]["services"].append({"id": "vpce-svc-0partner", "name": name, "acceptance": False,
                                             "allowed": ["*"]})  # fmt: skip
    core = acct("core-banking")
    if core and pay:
        net[core]["sg_refs"].append({"account": pay, "group": "sg-0payapp0demo", "ports": "tcp 5432",
                                     "groups": ["sg-0coredb0demo"]})  # fmt: skip
        net[core]["sg_cidrs"].append({"cidr": "192.168.100.0/24", "ports": "tcp 1433", "groups": ["sg-0coresql"]})
    for part, port in (
        ("legacy-batch", "tcp 22"),
        ("digital-channels-prod", "tcp 443"),
        ("merchant-portal", "tcp 443"),
    ):
        a = acct(part)
        if a:
            net[a]["sg_cidrs"].append({"cidr": "0.0.0.0/0", "ports": port, "groups": [f"sg-0{part[:6]}open"]})

    data = acct("data-platform-prod")
    if data:
        trusts[data].append({"role": "DatadogIntegration", "kind": "account", "id": VENDOR, "external_id": True,
                             "conditions": ["sts:ExternalId"]})  # fmt: skip
    digital = acct("digital-channels-prod")
    if digital:
        trusts[digital].append({"role": "github-deploy", "kind": "federated", "id": GITHUB.format(acct=digital),
                                "external_id": False,
                                "conditions": ["token.actions.githubusercontent.com:sub"]})  # fmt: skip
    sandbox = acct("sandbox-platform")
    if sandbox:
        trusts[sandbox].append({"role": "OrgReadOnly", "kind": "org", "id": "org", "external_id": False,
                                "conditions": ["aws:PrincipalOrgID"]})  # fmt: skip
    legacy = acct("legacy-batch")
    if legacy:
        trusts[legacy].append({"role": "batch-runner", "kind": "anyone", "id": "*", "external_id": False})
    if pay:
        trusts[pay].append({"role": "PartnerSettlement", "kind": "account", "id": PARTNER, "external_id": True})

    assets = _assets(ids, by_name, net, acct, rng)
    for aid in ids:
        facts = checked[aid].setdefault("facts", {})
        facts["access_network"] = {REGION: net[aid]}
        facts["access_trusts"] = trusts[aid]
        facts["access_assets"] = {REGION: assets[aid]}
    _edge_and_flows(checked, net, assets, acct)
    _failures(checked, assets, acct)
    _links(checked, net, assets, acct)
    logs = acct("log-archive")
    if logs:
        for b in checked[logs]["facts"].get("buckets") or []:
            b["grants"] = [{"kind": "org", "id": "org", "external_id": False, "conditions": ["aws:PrincipalOrgID"],
                            "actions": ["s3:PutObject"]}]  # fmt: skip
    if data:
        for b in checked[data]["facts"].get("buckets") or []:
            b["grants"] = [{"kind": "account", "id": VENDOR, "external_id": False, "actions": ["s3:GetObject"]}]
    # bucket policies and the networks they hold the bucket to
    for aid in ids:
        for b in checked[aid]["facts"].get("buckets") or []:
            b["has_policy"] = bool(b.get("grants") or b.get("tls_only"))
            if "settlement" in b["name"] or "card" in b["name"]:
                b["limits"] = {"vpce": [f"vpce-s3{aid[-6:]}"]}
            elif "partner" in b["name"]:
                b["limits"] = {"ip": ["196.25.1.0/24"]}
    return assurance


# ------------------------------------------------------------------------------- the account map


def _assets(ids, by_name, net, acct, rng) -> dict:
    """One VPC per account with public and private subnets, and the gateways the account's role suggests:
    internet-facing accounts get an internet gateway, NAT and a public load balancer; production
    workloads send other private ranges to the transit gateway; legacy-batch has a VPN and public
    servers, core-banking a Direct Connect line. The non-production gateway's route tables are read
    (shared-network owns it): sandboxes only reach the shared services."""
    name_of = {i: n for n, i in by_name.items()}
    out = {}
    public_facing = ("digital-channels", "merchant-portal", "partner-api", "mobile-backend", "onboarding")
    for aid in ids:
        name, cidr = name_of[aid], net[aid]["cidrs"][0]
        o2 = cidr.split(".")[1]
        vpc = f"vpc-{aid[-8:]}"
        att = next((a for a in net[aid]["tgw_attachments"]), None)
        facing = any(p in name for p in public_facing)
        x = {"vpcs": [{"id": vpc, "name": name.replace("-", " ").title().replace(" ", "-"), "cidrs": [cidr],
                       "default": False}],
             "subnets": [], "routes": [], "igws": [], "eigws": [], "nats": [], "vgws": [], "vpns": [],
             "dx_vifs": [], "tgw_peerings": [], "aws_endpoints": [], "public_ips": [], "lbs": [], "apis": [],
             "transfer": []}  # fmt: skip
        private_routes = []
        if att:
            private_routes.append({"dst": "10.0.0.0/8", "kind": "tgw", "target": att["tgw"], "blackhole": False})
            # the data centre, reached through the network hub's transit gateway
            private_routes.append({"dst": "172.16.0.0/12", "kind": "tgw", "target": att["tgw"], "blackhole": False})
        if facing or "legacy-batch" in name:
            x["igws"].append({"id": f"igw-{aid[-8:]}", "vpc": vpc})
            x["routes"].append({"id": f"rtb-pub-{aid[-6:]}", "vpc": vpc, "main": False, "subnets": 2, "routes": [
                {"dst": "0.0.0.0/0", "kind": "igw", "target": f"igw-{aid[-8:]}", "blackhole": False}]})  # fmt: skip
            x["subnets"].append({"id": f"subnet-pub-{aid[-6:]}", "vpc": vpc, "cidr": f"10.{o2}.0.0/24",
                                 "rt": f"rtb-pub-{aid[-6:]}"})  # fmt: skip
            x["nats"].append({"id": f"nat-{aid[-8:]}", "vpc": vpc, "subnet": f"subnet-pub-{aid[-6:]}",
                              "type": "public",
                              "public_ip": f"52.{rng.randint(16, 99)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
                              "private_ip": f"10.{o2}.0.10"})  # fmt: skip
            private_routes.append({"dst": "0.0.0.0/0", "kind": "nat", "target": f"nat-{aid[-8:]}", "blackhole": False})
        elif att:
            private_routes.append({"dst": "0.0.0.0/0", "kind": "tgw", "target": att["tgw"], "blackhole": False})
        x["routes"].append({"id": f"rtb-priv-{aid[-6:]}", "vpc": vpc, "main": True, "subnets": 3,
                            "routes": private_routes})  # fmt: skip
        x["subnets"].append({"id": f"subnet-priv-{aid[-6:]}", "vpc": vpc, "cidr": f"10.{o2}.16.0/20",
                             "rt": f"rtb-priv-{aid[-6:]}"})  # fmt: skip
        if facing:
            lb = f"{name.split('-prod')[0][:20]}-public"
            x["lbs"].append({"name": lb, "type": "application", "vpc": vpc,
                             "dns": f"{lb}-{aid[-4:]}.{REGION}.elb.amazonaws.com"})  # fmt: skip
            x["apis"].append({"id": f"a{aid[-6:]}", "name": f"{name.split('-prod')[0]}-api", "kind": "REST",
                              "endpoint": "REGIONAL", "default_endpoint": True})  # fmt: skip
        endpoints = [("s3", "Gateway"), ("dynamodb", "Gateway")] if "prod" in name else []
        if any(p in name for p in ("payments", "cards", "core-banking")):
            endpoints += [("kms", "Interface"), ("secretsmanager", "Interface"), ("sts", "Interface")]
        x["aws_endpoints"] = [{"id": f"vpce-{s[:6]}{aid[-6:]}", "service": s, "vpc": vpc, "type": t,
                               "open_policy": s == "s3"} for s, t in endpoints]  # fmt: skip
        for p in net[aid]["peerings"]:
            x["routes"][-1]["routes"].append({"dst": (p["accepter_cidrs"] if p["requester"] == aid
                                                      else p["requester_cidrs"])[0],
                                              "kind": "pcx", "target": p["id"], "blackhole": False})  # fmt: skip
        # Lambda functions: one outside a VPC, the rest in the private subnet
        short = name.split("-prod")[0].split("-uat")[0][:18]
        x["lambdas"] = [
            {"name": f"{short}-events", "runtime": "python3.13", "vpc": "", "subnets": [], "groups": [], "url": ""},
            {"name": f"{short}-worker", "runtime": "nodejs22.x", "vpc": vpc, "subnets": [f"subnet-priv-{aid[-6:]}"],
             "groups": [f"sg-0{short[:6]}fn"], "url": ""},
        ]  # fmt: skip
        if facing:
            x["lambdas"].append({"name": f"{short}-webhook", "runtime": "python3.13", "vpc": "", "subnets": [],
                                 "groups": [], "url": "NONE"})  # fmt: skip
        out[aid] = x
    legacy, core, data = acct("legacy-batch"), acct("core-banking"), acct("data-platform-prod")
    if legacy:
        x = out[legacy]
        vpc = x["vpcs"][0]["id"]
        x["vgws"].append({"id": "vgw-0legacy", "vpcs": [vpc], "asn": 64512})
        x["vpns"].append({"id": "vpn-0datacentre", "gateway": "vgw-0legacy", "customer_ip": "196.25.1.10",
                          "name": "Johannesburg data centre", "tunnels": 2, "up": 1,
                          "routes": ["192.168.0.0/16"]})  # fmt: skip
        x["routes"][-1]["routes"].append({"dst": "192.168.0.0/16", "kind": "vgw", "target": "vgw-0legacy",
                                          "blackhole": False})  # fmt: skip
        x["public_ips"] = [{"id": f"eni-0legacy{i}", "ip": f"34.240.{i}.{20 + i}", "vpc": vpc,
                            "private_ip": f"10.0.0.{40 + i}", "what": "EC2 instance",
                            "groups": ["sg-0legacyopen"]} for i in range(3)]  # fmt: skip
        x["transfer"].append({"id": "s-0legacyftp", "endpoint": "PUBLIC", "state": "ONLINE"})
    if core:
        x = out[core]
        x["vgws"].append({"id": "vgw-0core", "vpcs": [x["vpcs"][0]["id"]], "asn": 64513})
        x["dx_vifs"].append({"id": "dxvif-0core", "name": "core-to-dc1", "type": "private", "location": "TCJH1",
                             "gateway": "vgw-0core", "state": "available"})  # fmt: skip
    if data:
        out[data]["transfer"].append({"id": "s-0partnerdrop", "endpoint": "VPC", "state": "ONLINE"})
    hub = acct("shared-network")
    np_atts = [(aid, a) for aid in ids for a in net[aid]["tgw_attachments"] if a["tgw"] == "tgw-0nonprod"]
    if hub and np_atts:
        sandboxes = [a["id"] for aid, a in np_atts if "sandbox" in name_of[aid]]
        shared = [a for aid, a in np_atts if aid == hub or "log-archive" in name_of[aid]]
        workloads = [a["id"] for aid, a in np_atts if a["id"] not in sandboxes]
        routes = [{"dst": net[aid]["cidrs"][0], "attachments": [a["id"]], "type": "propagated", "blackhole": False}
                  for aid, a in np_atts]  # fmt: skip
        routes.append({"dst": "10.250.0.0/16", "attachments": [], "type": "static", "blackhole": True})
        out[hub]["tgw_tables"] = [
            {"id": "tgw-rtb-0nonprod", "tgw": "tgw-0nonprod", "name": "non-production", "associations": workloads,
             "propagations": workloads, "routes": routes, "routes_cut": False},
            {"id": "tgw-rtb-0sandbox", "tgw": "tgw-0nonprod", "name": "sandboxes", "associations": sandboxes,
             "propagations": [], "routes": [{"dst": net[aid]["cidrs"][0], "attachments": [a["id"]],
                                             "type": "static", "blackhole": False} for aid, a in np_atts
                                            if a in shared], "routes_cut": False},
        ]  # fmt: skip
    return out


def _hours(peak: float, floor: float = 0.25, down: tuple = ()) -> list:
    """24 hourly values on a working-day curve, oldest first; hours in ``down`` are 0."""
    from datetime import datetime, timedelta, timezone

    end = datetime(2026, 11, 17, 10, tzinfo=timezone.utc)
    out = []
    for i in range(24):
        t = end - timedelta(hours=23 - i)
        h = (t.hour + 2) % 24  # local time
        shape = floor + (1 - floor) * max(0.0, 1 - abs(h - 13) / 8)
        out.append([t.isoformat(), 0.0 if i in down else round(peak * shape, 2)])
    return out


def _series(peak: float, floor: float = 0.25, down: tuple = ()) -> dict:
    h = _hours(peak, floor, down)
    vals = [v for _, v in h]
    return {"sum": round(sum(vals), 2), "max": max(vals), "min": min(vals), "n": 24, "hours": h}


def _flat(total: float, stat: str = "sum") -> dict:
    return {"sum": total, "max": total if stat == "max" else round(total / 24, 2),
            "min": total if stat == "max" else 0.0, "n": 24}  # fmt: skip


def _links(checked, net, assets, acct) -> None:
    """How the network links carried traffic and failed: the non-production transit gateway (a blackhole route
    dropping a sandbox's traffic), Direct Connect into core banking (one line near full, one that dropped with
    CRC errors), the legacy VPN on one tunnel, NAT gateways, and the payments PrivateLink service."""

    def links(aid) -> dict:
        return checked[aid]["facts"]["access_failures"][REGION].setdefault("links", {})

    hub = acct("shared-network")
    np_atts = [(aid, a) for aid in checked for a in net[aid]["tgw_attachments"] if a["tgw"] == "tgw-0nonprod"]
    if hub and np_atts:
        att = {}
        for i, (_aid, a) in enumerate(np_atts):
            gb = 4e9 / (i + 1)
            att[f"tgw-0nonprod|{a['id']}"] = {"tgwa_in": _series(gb / 24 * 2.2), "tgwa_out": _series(gb / 24 * 1.6),
                                              "tgwa_hole": _flat(0), "tgwa_noroute": _flat(0)}  # fmt: skip
        att[f"tgw-0nonprod|{np_atts[0][1]['id']}"]["tgwa_hole"] = _flat(2_140)
        if len(np_atts) > 2:
            att[f"tgw-0nonprod|{np_atts[-1][1]['id']}"] = {k: _flat(0) for k in ("tgwa_in", "tgwa_out", "tgwa_hole",
                                                                              "tgwa_noroute")}  # fmt: skip
        links(hub)["tgwa"] = att
        links(hub)["tgw"] = {"tgw-0nonprod": {
            "tgw_in": _series(sum(x["tgwa_in"]["sum"] for x in att.values()) / 24 * 1.6),
            "tgw_out": _series(sum(x["tgwa_out"]["sum"] for x in att.values()) / 24 * 1.6),
            "tgw_hole": _flat(2_140), "tgw_noroute": _flat(380)}}  # fmt: skip
    core = acct("core-banking")
    if core:
        checked[core]["facts"]["access_failures"][REGION]["dx"] = [
            {"id": "dxcon-0core1", "name": "core-dc1-primary", "location": "TCJH1", "bandwidth": "10Gbps",
             "state": "available", "partner": "", "lag": "", "vlan": None, "has_logical_redundancy": "no"},
            {"id": "dxcon-0core2", "name": "core-dc2-secondary", "location": "TCCT1", "bandwidth": "1Gbps",
             "state": "available", "partner": "Example Carrier", "lag": "", "vlan": 412,
             "has_logical_redundancy": "no"},
        ]  # fmt: skip
        links(core)["dx"] = {
            "dxcon-0core1": {"dx_state": _series(1, 1), "dx_in_max": _series(8.6e9, 0.2),
                             "dx_out_max": _series(6.1e9, 0.2), "dx_in": _series(5.2e9, 0.2),
                             "dx_out": _series(3.8e9, 0.2), "dx_err": _flat(0), "dx_crc": _flat(0),
                             "dx_light": _flat(-3.1, "max")},
            "dxcon-0core2": {"dx_state": _series(1, 1, down=(3, 4, 5)), "dx_in_max": _series(2.1e8, 0.3),
                             "dx_out_max": _series(1.4e8, 0.3), "dx_in": _series(1.2e8, 0.3),
                             "dx_out": _series(0.9e8, 0.3), "dx_err": _flat(37), "dx_crc": _flat(1_204),
                             "dx_light": _flat(-13.9, "max")},
        }  # fmt: skip
        links(core)["vif"] = {
            "dxcon-0core1|dxvif-0core": {"vif_in": _flat(8.1e9, "max"), "vif_out": _flat(5.9e9, "max")}
        }
    legacy = acct("legacy-batch")
    if legacy:
        links(legacy)["vpn"] = {
            "vpn-0datacentre|52.48.1.10": {"vpn_state": _series(1, 1, down=(14,)), "vpn_in": _flat(3.4e9),
                                           "vpn_out": _flat(1.1e9)},
            "vpn-0datacentre|52.48.1.11": {"vpn_state": _series(1, 1, down=tuple(range(24))), "vpn_in": _flat(0),
                                           "vpn_out": _flat(0)},
        }  # fmt: skip
    for aid, x in assets.items():
        for n in x["nats"]:
            tried, lost = 48_000, 0
            if aid == acct("digital-channels-prod"):
                lost = 96
            if aid == acct("legacy-batch"):
                tried, lost = 220_000, 3_900
            links(aid).setdefault("nat", {})[n["id"]] = {
                "nat_try": _series(tried / 24 * 1.8), "nat_made": _series((tried - lost) / 24 * 1.8),
                "nat_port": _flat(312 if aid == acct("legacy-batch") else 0), "nat_drop": _flat(0),
                "nat_idle": _flat(140),
                "nat_active": _flat(2_400, "max"), "nat_out": _flat(2.6e9), "nat_in": _flat(9.8e9)}  # fmt: skip
    pay = acct("payments-core-prod")
    if pay and net[pay]["services"]:
        sid = net[pay]["services"][0]["id"]
        name = net[pay]["services"][0]["name"]
        consumers = [(b, e["id"]) for b in checked if b != pay for e in net[b]["endpoints"]
                     if e.get("service") == name][:3]  # fmt: skip
        links(pay)["vpcs"] = {sid: {"vpcs_bytes": _flat(6.4e9), "vpcs_new": _flat(182_000), "vpcs_rst": _flat(860),
                                    "vpcs_eps": _flat(max(len(consumers), 1), "max")}}  # fmt: skip
        links(pay)["vpcse"] = {f"{sid}|{ep}": {"vpcse_bytes": _flat(6.4e9 / (i + 1)),
                                               "vpcse_rst": _flat(860 if i == 0 else 0)}
                               for i, (_b, ep) in enumerate(consumers)}  # fmt: skip
        for i, (b, ep) in enumerate(consumers):
            links(b).setdefault("vpce", {})[f"{ep}|{name}|vpc-{b[-8:]}"] = {
                "vpce_bytes": _flat(6.4e9 / (i + 1)), "vpce_new": _flat(60_000), "vpce_drop": _flat(0),
                "vpce_rst": _flat(860 if i == 0 else 0)}  # fmt: skip
    # traffic with the data centre behind the legacy VPN, and the database there
    dig = acct("digital-channels-prod")
    fl = (checked.get(dig, {}).get("facts", {}).get("access_flows") or {}).get(REGION) if dig else None
    if fl:
        app = fl["rows"][0]["src"]
        fl["rows"] += [
            {"src": app, "dst": "192.168.10.5", "port": "1521", "bytes": 1_900_000_000, "flows": 14_000},
            {"src": "192.168.10.5", "dst": app, "port": "8443", "bytes": 240_000_000, "flows": 3_100},
            {"src": app, "dst": "192.168.40.12", "port": "445", "bytes": 610_000_000, "flows": 900},
        ]


def _edge_and_flows(checked, net, assets, acct) -> None:
    """CloudFront in front of the public accounts, and a day of flow-log evidence in two of them."""
    for part in ("digital-channels-prod", "merchant-portal"):
        a = acct(part)
        if a:
            lb = (assets[a]["lbs"] or [{}])[0].get("dns", "")
            checked[a]["facts"]["cloudfront"] = [{"id": f"E{a[-8:]}", "domain": f"d{a[-6:]}.cloudfront.net",
                                                  "waf": part != "merchant-portal", "origins": [lb]}]  # fmt: skip
    for part in ("digital-channels-prod", "payments-core-prod"):
        a = acct(part)
        if not a:
            continue
        x, o2 = assets[a], net[a]["cidrs"][0].split(".")[1]
        rows = []
        app = f"10.{o2}.17.21"
        others = [b for b in checked if b != a and net[b]["tgw_attachments"]][:4]
        for i, b in enumerate(others):
            o = net[b]["cidrs"][0].split(".")[1]
            rows.append({"src": app, "dst": f"10.{o}.17.{30 + i}", "port": "5432" if i == 0 else "443",
                         "bytes": 9_000_000_000 // (i + 1), "flows": 40_000 // (i + 1)})  # fmt: skip
            rows.append({"src": f"10.{o}.17.{30 + i}", "dst": app, "port": "8443", "bytes": 700_000_000 // (i + 1),
                         "flows": 9000})  # fmt: skip
        if x["nats"]:
            nat_ip = x["nats"][0]["private_ip"]
            rows += [{"src": nat_ip, "dst": "151.101.1.69", "port": "443", "bytes": 2_400_000_000, "flows": 12000},
                     {"src": nat_ip, "dst": "140.82.121.4", "port": "443", "bytes": 310_000_000, "flows": 800},
                     {"src": "41.13.200.7", "dst": f"10.{o2}.0.44", "port": "443", "bytes": 5_100_000_000,
                      "flows": 220000}]  # fmt: skip
        else:
            rows.append({"src": app, "dst": "52.94.5.100", "port": "443", "bytes": 1_200_000_000, "flows": 3000})
        rows.append({"src": app, "dst": f"10.{o2}.16.9", "port": "6379", "bytes": 4_000_000_000, "flows": 90000})
        total = sum(r["bytes"] for r in rows)
        # refused: a scan of the public edge, a database port probed, one blocked call out
        target = f"10.{o2}.0.44" if x["nats"] else app
        rejected = [{"src": "185.220.101.34", "dst": target, "port": "22", "bytes": 4_100_000, "flows": 6100},
                    {"src": "45.155.205.233", "dst": target, "port": "3389", "bytes": 2_200_000, "flows": 3400},
                    {"src": "193.163.125.12", "dst": target, "port": "445", "bytes": 900_000, "flows": 1200},
                    {"src": f"10.{net[others[0]]['cidrs'][0].split('.')[1]}.17.30" if others else "10.250.0.9",
                     "dst": app, "port": "5432", "bytes": 120_000, "flows": 310},
                    {"src": app, "dst": "91.198.174.192", "port": "443", "bytes": 40_000, "flows": 95}]  # fmt: skip
        checked[a]["facts"]["access_flows"] = {REGION: {
            "hours": 24, "rows": rows, "total_bytes": int(total * 1.04), "covered": [x["vpcs"][0]["id"]],
            "s3_only": [], "unreadable": [], "rejected": rejected, "reject_covered": [x["vpcs"][0]["id"]]}}  # fmt: skip
        # the day's totals with the internet, as the flow-log query counts them: more than the largest rows show
        pub = lambda v: not v.startswith("10.")  # noqa: E731
        sent = [r for r in rows if pub(r["dst"])]
        got = [r for r in rows if pub(r["src"])]
        checked[a]["facts"]["access_flows"][REGION]["internet"] = {
            "out": {"bytes": int(sum(r["bytes"] for r in sent) * 1.3), "flows": sum(r["flows"] for r in sent) * 2,
                    "ips": 140 if x["nats"] else 12},
            "in": {"bytes": int(sum(r["bytes"] for r in got) * 1.2), "flows": sum(r["flows"] for r in got) * 2,
                   "ips": 2600 if x["nats"] else 0}}  # fmt: skip


def _failures(checked, assets, acct) -> None:
    """A day of failed and blocked traffic: every account's metrics read (mostly 0), a probe of the public
    edge in the two flow-logged accounts, and refused API calls from an organisation trail."""
    from .collectors.access import FAIL_METRICS

    for aid, x in assets.items():
        lbs = [f"app/{lb['name']}/{aid[-6:]}0demo" for lb in x["lbs"]]
        metrics = {k: {"total": 0, "top": [], "resources": 0} for k in FAIL_METRICS}
        present = {"alb": len(lbs), "nat": len(x["nats"]), "api_rest": len(x["apis"]), "waf": 1 if lbs else 0}

        def put(key, name, value, metrics=metrics):
            metrics[key] = {"total": value, "top": [[name, value]], "resources": 1}

        if lbs and acct("digital-channels-prod") == aid:
            put("alb_elb_4xx", lbs[0], 18_420)
            put("alb_tls", lbs[0], 2_310)
            put("alb_target_5xx", lbs[0], 41)
            put("waf_blocked", f"{x['lbs'][0]['name']}-acl", 9_870)
            put("api_rest_4xx", x["apis"][0]["name"], 3_405)
        if lbs and acct("payments-core-prod") == aid:
            put("alb_elb_4xx", lbs[0], 2_150)
            put("waf_blocked", f"{x['lbs'][0]['name']}-acl", 1_204)
        if x["nats"] and acct("legacy-batch") == aid:
            put("nat_port", x["nats"][0]["id"], 312)
        if x["nats"] and acct("payments-core-prod") == aid:
            put("nat_unanswered", x["nats"][0]["id"], 1_840)
        if x["nats"] and acct("digital-channels-prod") == aid:
            put("nat_unanswered", x["nats"][0]["id"], 96)
        checked[aid]["facts"]["access_failures"] = {REGION: {"hours": 24, "metrics": metrics, "present": present}}
    scanners = ["185.220.101.34", "45.155.205.233"]
    for part, extra in (("digital-channels-prod", 0), ("payments-core-prod", 1)):
        a = acct(part)
        fl = (checked.get(a, {}).get("facts", {}).get("access_flows") or {}).get(REGION) if a else None
        if not fl:
            continue
        target = fl["rejected"][0]["dst"]
        # one address sweeping many ports: what a scan looks like in the flow logs
        fl["rejected"] += [
            {"src": scanners[extra], "dst": target, "port": p, "bytes": 60 * n, "flows": n}
            for p, n in (
                ("21", 40),
                ("23", 38),
                ("25", 31),
                ("80", 29),
                ("1433", 27),
                ("3306", 26),
                ("5900", 22),
                ("6379", 20),
                ("8080", 18),
                ("9200", 15),
            )
        ]
    _tcp_and_new(checked, acct)
    mgmt = acct("management") or next(iter(checked))
    who = "arn:aws:sts::{a}:assumed-role/ci-readonly/session"
    rows = []
    for part, ip, n in (
        ("digital-channels-prod", "185.220.101.34", 1),
        ("payments-core-prod", "185.220.101.34", 1),
        ("legacy-batch", "102.68.4.19", 3),
    ):
        a = acct(part)
        if not a:
            continue
        caller = f"arn:aws:iam::{a}:user/legacy-sync" if part == "legacy-batch" else who.format(a=a)
        for svc, call in (
            ("iam", "ListUsers"),
            ("iam", "ListRoles"),
            ("s3", "ListBuckets"),
            ("ec2", "DescribeInstances"),
            ("secretsmanager", "ListSecrets"),
            ("kms", "ListKeys"),
            ("sts", "GetCallerIdentity"),
            ("organizations", "ListAccounts"),
            ("lambda", "ListFunctions"),
            ("rds", "DescribeDBInstances"),
            ("ssm", "GetParameters"),
            ("guardduty", "ListDetectors"),
        ):
            rows.append(
                {
                    "account": a,
                    "who": caller,
                    "ip": ip,
                    "svc": f"{svc}.amazonaws.com",
                    "call": call,
                    "code": "AccessDenied" if svc in ("iam", "s3") else "AccessDeniedException",
                    "n": 4 * n,
                }
            )
        rows.append(
            {
                "account": a,
                "who": f"arn:aws:iam::{a}:user/build",
                "ip": "10.40.17.9",
                "svc": "s3.amazonaws.com",
                "call": "PutObject",
                "code": "AccessDenied",
                "n": 220,
            }
        )
        rows.append(
            {
                "account": a,
                "who": "root",
                "ip": "196.25.7.80",
                "svc": "signin.amazonaws.com",
                "call": "ConsoleLogin",
                "code": "",
                "n": 6 * n,
            }
        )
    totals: dict[str, int] = {}
    for r in rows:
        totals[r["account"]] = totals.get(r["account"], 0) + r["n"]
    checked[mgmt]["facts"]["trail_denials"] = {
        "hours": 24,
        "read": True,
        "org": True,
        "rows": sorted(rows, key=lambda r: -r["n"]),
        "totals": totals,
        "trails": [{"name": "org-trail", "org": True, "group": "aws-controltower/CloudTrailLogs", "region": REGION}],
    }


def _tcp_and_new(checked, acct) -> None:
    """Connections nobody answered and resets in the two flow-logged accounts, one host inside the estate
    sweeping another's ports today, and what is new against the week before: the Network Traffic Review."""
    for part in ("digital-channels-prod", "payments-core-prod"):
        a = acct(part)
        fl = (checked.get(a, {}).get("facts", {}).get("access_flows") or {}).get(REGION) if a else None
        if not fl:
            continue
        app = fl["rows"][0]["src"]
        peer = fl["rows"][0]["dst"]
        tcp = [{"src": app, "dst": peer, "port": "5432", "kind": "unanswered", "flows": 420, "packets": 1680,
                "bytes": 100_800},
               {"src": app, "dst": "10.250.4.12", "port": "1521", "kind": "unanswered", "flows": 96, "packets": 384,
                "bytes": 23_040},
               {"src": peer, "dst": app, "port": "8080", "kind": "reset", "flows": 1_210, "packets": 1_210,
                "bytes": 48_400}]  # fmt: skip
        if part == "digital-channels-prod":
            # a host inside the estate trying port after port on another: new today
            tcp += [
                {
                    "src": app,
                    "dst": peer,
                    "port": p,
                    "kind": "reset",
                    "flows": 3,
                    "packets": 3,
                    "bytes": 120,
                    "new": True,
                    "src_new": True,
                }
                for p in ("21", "22", "23", "25", "135", "139", "445", "1433", "3306", "3389", "5900", "6379")
            ]
        fl["failed_tcp"] = tcp
        fl["tcp_covered"] = list(fl["reject_covered"])
        fl["baseline"] = {"days": 7, "read": True, "full": False, "pairs": 3_412}
        fl["insights_bytes"] = 38_000_000_000 if part == "digital-channels-prod" else 21_000_000_000
        for r in (*fl["rejected"], *tcp):
            r.setdefault("new", r["src"] == "45.155.205.233" or r["dst"] in ("91.198.174.192", "10.250.4.12"))
            r.setdefault("src_new", r["src"] == "45.155.205.233")
