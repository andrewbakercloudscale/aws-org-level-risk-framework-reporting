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
