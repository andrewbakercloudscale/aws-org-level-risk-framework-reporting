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

    for aid in ids:
        facts = checked[aid].setdefault("facts", {})
        facts["access_network"] = {REGION: net[aid]}
        facts["access_trusts"] = trusts[aid]
    logs = acct("log-archive")
    if logs:
        for b in checked[logs]["facts"].get("buckets") or []:
            b["grants"] = [{"kind": "org", "id": "org", "external_id": False, "conditions": ["aws:PrincipalOrgID"],
                            "actions": ["s3:PutObject"]}]  # fmt: skip
    if data:
        for b in checked[data]["facts"].get("buckets") or []:
            b["grants"] = [{"kind": "account", "id": VENDOR, "external_id": False, "actions": ["s3:GetObject"]}]
    return assurance
