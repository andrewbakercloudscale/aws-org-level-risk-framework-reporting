"""Access Graph: the facts read in each account, and the account-to-account edges built from them."""

import json

from test_assurance import FakeClient, _ctx
from test_server import H, client

import exitrisk.collectors.assurance as checks
from exitrisk.access_graph import build_access
from exitrisk.collectors import access
from exitrisk.demo import build_demo_scan
from exitrisk.filtering import AccountFilter

OWN, PEER, VENDOR, HUB = "111111111111", "222222222222", "999999999999", "333333333333"
GITHUB = f"arn:aws:iam::{OWN}:oidc-provider/token.actions.githubusercontent.com"


# ---------------------------------------------------------------------------------- policies


def _trust(principal, condition=None):
    st = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if condition:
        st["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [st]}


def test_role_trusts_keep_every_outside_principal_and_drop_services_and_own_account():
    doc = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": [f"arn:aws:iam::{PEER}:root", f"arn:aws:iam::{OWN}:role/x"]},
         "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"Federated": GITHUB},
         "Action": "sts:AssumeRoleWithWebIdentity"},
        {"Effect": "Deny", "Principal": {"AWS": VENDOR}, "Action": "sts:AssumeRole"},
    ]}  # fmt: skip
    got = access.role_trusts("deploy", json.dumps(doc), OWN)
    assert [(t["kind"], t["id"]) for t in got] == [
        ("account", PEER),
        ("federated", GITHUB),
    ]
    assert all(t["role"] == "deploy" for t in got)


def test_star_principal_reads_as_anyone_org_or_the_named_accounts():
    def kinds(cond):
        return [(t["kind"], t["id"]) for t in access.role_trusts("r", _trust("*", cond), OWN)]

    assert kinds(None) == [("anyone", "*")]
    assert kinds({"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}) == [("org", "org")]
    assert kinds({"StringEquals": {"aws:PrincipalAccount": PEER}}) == [("account", PEER)]


def test_external_id_and_condition_keys_are_kept():
    got = access.role_trusts("vendor", _trust({"AWS": VENDOR}, {"StringEquals": {"sts:ExternalId": "x"}}), OWN)
    assert got == [{"role": "vendor", "kind": "account", "id": VENDOR, "external_id": True,
                    "conditions": ["sts:ExternalId"]}]  # fmt: skip


def test_bucket_policy_grants_merge_actions_per_principal():
    policy = json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{VENDOR}:root"}, "Action": "s3:GetObject",
         "Resource": "*"},
        {"Effect": "Allow", "Principal": {"AWS": VENDOR}, "Action": ["s3:ListBucket"], "Resource": "*"},
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"},
    ]})  # fmt: skip
    assert access.policy_grants(policy, OWN) == [
        {"kind": "account", "id": VENDOR, "external_id": False, "actions": ["s3:GetObject", "s3:ListBucket"]}
    ]


# ---------------------------------------------------------------------------------- network facts


def test_ingress_sources_skip_own_vpcs_and_unattached_groups():
    groups = [
        {"GroupId": "sg-db", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
             "IpRanges": [{"CidrIp": "10.1.0.0/16"}, {"CidrIp": "10.0.0.0/8"}],
             "UserIdGroupPairs": [{"UserId": PEER, "GroupId": "sg-app"}, {"UserId": OWN, "GroupId": "sg-own"}]}]},
        {"GroupId": "sg-spare", "IpPermissions": [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
    ]  # fmt: skip
    got = access.ingress_sources(groups, OWN, ["10.1.0.0/16"], in_use={"sg-db"})
    assert got["refs"] == [{"account": PEER, "group": "sg-app", "ports": "tcp 5432", "groups": ["sg-db"]}]
    assert got["cidrs"] == [{"cidr": "10.0.0.0/8", "ports": "tcp 5432", "groups": ["sg-db"]}]


def test_network_task_records_peerings_gateways_privatelink_and_ingress():
    ec2 = FakeClient({
        "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.1.0.0/16",
                                    "CidrBlockAssociationSet": [{"CidrBlock": "10.1.0.0/16",
                                                                 "CidrBlockState": {"State": "associated"}}]}]},
        "describe_vpc_peering_connections": {"VpcPeeringConnections": [
            {"VpcPeeringConnectionId": "pcx-1", "RequesterVpcInfo": {"OwnerId": OWN, "Region": "eu-west-1"},
             "AccepterVpcInfo": {"OwnerId": PEER, "Region": "eu-west-1",
                                 "CidrBlockSet": [{"CidrBlock": "10.2.0.0/16"}]}}]},
        "describe_transit_gateway_attachments": {"TransitGatewayAttachments": [
            {"TransitGatewayAttachmentId": "tgw-attach-1", "TransitGatewayId": "tgw-1", "TransitGatewayOwnerId": HUB,
             "ResourceOwnerId": OWN, "ResourceType": "vpc", "ResourceId": "vpc-1", "State": "available"},
            {"TransitGatewayAttachmentId": "tgw-attach-2", "TransitGatewayId": "tgw-1", "TransitGatewayOwnerId": HUB,
             "ResourceOwnerId": OWN, "ResourceType": "vpc", "ResourceId": "vpc-9", "State": "deleted"}]},
        "describe_vpc_endpoint_service_configurations": {"ServiceConfigurations": [
            {"ServiceId": "vpce-svc-1", "ServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-1",
             "ServiceState": "Available"}]},
        "describe_vpc_endpoint_service_permissions": {
            "AllowedPrincipals": [{"Principal": f"arn:aws:iam::{VENDOR}:root"}]},
        "describe_vpc_endpoints": {"VpcEndpoints": [
            {"VpcEndpointId": "vpce-1", "ServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-9", "State": "available"},
            {"VpcEndpointId": "vpce-2", "ServiceName": "com.amazonaws.eu-west-1.s3", "State": "available"}]},
        "describe_network_interfaces": {"NetworkInterfaces": [{"Groups": [{"GroupId": "sg-db"}]}]},
        "describe_security_groups": {"SecurityGroups": [{"GroupId": "sg-db", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
    })  # fmt: skip
    ctx = _ctx({"ec2": ec2})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "access-network"), "eu-west-1")
    assert not ctx.issues
    n = ctx.r.facts["access_network"]["eu-west-1"]
    assert n["cidrs"] == ["10.1.0.0/16"]
    assert [p["accepter"] for p in n["peerings"]] == [PEER]
    assert [(a["tgw"], a["tgw_owner"]) for a in n["tgw_attachments"]] == [("tgw-1", HUB)]  # deleted one left out
    assert n["services"][0]["allowed"] == [f"arn:aws:iam::{VENDOR}:root"]
    assert [e["id"] for e in n["endpoints"]] == ["vpce-1"]  # AWS service endpoints are not account paths
    assert n["sg_cidrs"] == [{"cidr": "0.0.0.0/0", "ports": "tcp 22", "groups": ["sg-db"]}]


def test_network_task_refused_is_an_issue_not_a_crash():
    ctx = _ctx({"ec2": FakeClient()})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "access-network"), "eu-west-1")
    assert ctx.issues and "access-network" in ctx.issues[0].message
    assert "access_network" not in ctx.r.facts


def test_bucket_policy_is_read_once_for_tls_and_grants():
    policy = json.dumps({"Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        {"Effect": "Allow", "Principal": {"AWS": VENDOR}, "Action": "s3:GetObject", "Resource": "*"}]})  # fmt: skip
    calls = []

    def get_policy(Bucket):  # noqa: N803
        calls.append(Bucket)
        return {"Policy": policy}

    s3 = FakeClient({"list_buckets": {"Buckets": [{"Name": "b1", "BucketRegion": "eu-west-1"}]},
                     "get_bucket_policy": get_policy})  # fmt: skip
    s3c = FakeClient({"get_public_access_block": {"PublicAccessBlockConfiguration": {}}})
    ctx = _ctx({"s3": s3, ("s3", "eu-west-1"): s3, "s3control": s3c})
    checks._run(ctx, next(t for t in checks.GLOBAL_TASKS if t[0] == "s3"), None)
    b = ctx.r.facts["buckets"][0]
    assert calls == ["b1"]
    assert b["tls_only"] is True
    assert b["grants"][0]["id"] == VENDOR and "policy" not in b


# ---------------------------------------------------------------------------------- the graph


def _scan(facts_by_account, names=None):
    names = names or {}
    return {
        "id": "s1", "created_at": "2026-11-17T00:00:00+00:00",
        "accounts": [{"id": a, "name": names.get(a, f"acct-{a[:3]}")} for a in facts_by_account],
        "org_accounts": {HUB: {"name": "network-hub", "ou_path": "Root"}},
        "assurance": {"accounts": {a: {"facts": f} for a, f in facts_by_account.items()}},
    }  # fmt: skip


def _net(cidr, **kw):
    return {"eu-west-1": {"cidrs": [cidr], "peerings": [], "tgw_attachments": [], "services": [], "endpoints": [],
                          "sg_refs": [], "sg_cidrs": [], **kw}}  # fmt: skip


def _edges(r, etype=None):
    return {(e["from"], e["to"]) for e in r["edges"] if etype is None or e["type"] == etype}


def test_security_group_range_needs_a_route_to_count():
    third = "444444444444"
    attach = lambda a: [{"tgw": "tgw-1", "tgw_owner": HUB, "owner": a, "type": "vpc"}]  # noqa: E731
    scan = _scan({
        OWN: {"access_network": _net("10.1.0.0/16", tgw_attachments=attach(OWN),
                                     sg_cidrs=[{"cidr": "10.0.0.0/8", "ports": "tcp 5432", "groups": ["sg-db"]}])},
        PEER: {"access_network": _net("10.2.0.0/16", tgw_attachments=attach(PEER))},
        third: {"access_network": _net("10.3.0.0/16")},  # inside 10/8, but no route to OWN
    })  # fmt: skip
    r = build_access(scan)
    assert _edges(r, "sg-cidr") == {(PEER, OWN)}
    assert (third, OWN) not in _edges(r)
    assert {("tgw:tgw-1", OWN), (OWN, "tgw:tgw-1"), (PEER, "tgw:tgw-1"), (HUB, "tgw:tgw-1")} <= _edges(r, "tgw")
    hub = next(n for n in r["nodes"] if n["id"] == HUB)
    assert hub["kind"] == "org" and hub["label"] == "network-hub"  # named, though not scanned


def test_unowned_ranges_go_to_other_networks_and_world_to_the_internet():
    scan = _scan({OWN: {"access_network": _net("10.1.0.0/16", sg_cidrs=[
        {"cidr": "192.168.7.0/24", "ports": "tcp 1433", "groups": ["sg-sql"]},
        {"cidr": "0.0.0.0/0", "ports": "tcp 22", "groups": ["sg-ssh"]},
        {"cidr": "52.95.0.0/16", "ports": "tcp 443", "groups": ["sg-web"]}])}})  # fmt: skip
    r = build_access(scan)
    assert _edges(r) == {("net:private", OWN), ("internet", OWN), ("net:public", OWN)}
    assert r["stats"]["internet_exposed"] == 1


def test_iam_edges_name_the_role_and_the_outside_party():
    scan = _scan({OWN: {
        "access_trusts": [
            {"role": "audit", "kind": "account", "id": PEER, "external_id": False},
            {"role": "vendor", "kind": "account", "id": VENDOR, "external_id": True},
            {"role": "open", "kind": "anyone", "id": "*", "external_id": False},
        ],
        "buckets": [{"name": "logs", "grants": [{"kind": "org", "id": "org", "actions": ["s3:PutObject"]}]}],
    }, PEER: {"access_trusts": []}})  # fmt: skip
    r = build_access(scan)
    assert _edges(r, "role-trust") == {(PEER, OWN), (VENDOR, OWN), ("anyone", OWN)}
    assert _edges(r, "bucket-policy") == {("org", OWN)}
    vendor = next(e for e in r["edges"] if e["from"] == VENDOR)
    assert vendor["details"] == ["role vendor (external id)"] and vendor["kind"] == "iam"
    assert next(n for n in r["nodes"] if n["id"] == VENDOR)["kind"] == "external"


def test_privatelink_connects_consumer_to_provider():
    svc = "com.amazonaws.vpce.eu-west-1.vpce-svc-1"
    scan = _scan({
        OWN: {"access_network": _net("10.1.0.0/16", services=[
            {"id": "vpce-svc-1", "name": svc, "allowed": [f"arn:aws:iam::{VENDOR}:root"], "acceptance": True}])},
        PEER: {"access_network": _net("10.2.0.0/16", endpoints=[{"id": "vpce-9", "service": svc}])},
    })  # fmt: skip
    assert _edges(build_access(scan), "privatelink") == {(VENDOR, OWN), (PEER, OWN)}


def test_peering_is_both_ways():
    p = {"id": "pcx-1", "requester": OWN, "accepter": PEER}
    scan = _scan({OWN: {"access_network": _net("10.1.0.0/16", peerings=[p])},
                  PEER: {"access_network": _net("10.2.0.0/16", peerings=[p])}})  # fmt: skip
    assert _edges(build_access(scan), "peering") == {(OWN, PEER), (PEER, OWN)}


def test_not_available_without_assurance_or_without_the_new_facts():
    assert build_access({"accounts": []})["available"] is False
    old = _scan({OWN: {"buckets": []}})
    r = build_access(old)
    assert r["available"] is False and "before the Access Graph" in r["reason"]


def test_account_filter_drops_accounts_and_their_facts():
    scan = _scan({OWN: {"access_trusts": [{"role": "r", "kind": "account", "id": VENDOR}]},
                  PEER: {"access_trusts": [{"role": "r", "kind": "account", "id": VENDOR}]}},
                 names={OWN: "payments-prod", PEER: "sandbox"})  # fmt: skip
    r = build_access(scan, AccountFilter(include="prod"))
    assert [a["id"] for a in r["accounts"]] == [OWN]
    assert _edges(r) == {(VENDOR, OWN)}


def test_demo_tells_the_story():
    r = build_access(build_demo_scan(12))
    assert r["available"] and not r["notes"]
    names = {n["id"]: n["label"] for n in r["nodes"]}
    by_name = {v: k for k, v in names.items()}
    pay = by_name["payments-core-prod"]
    # The 10.0.0.0/8 database rule: every account on the production gateway reaches payments.
    assert sum(1 for e in r["edges"] if e["to"] == pay and e["type"] == "sg-cidr") > 10
    assert r["accounts"][0]["id"] == pay
    assert ("anyone", by_name["legacy-batch-prod"]) in _edges(r, "role-trust")
    assert ("internet", by_name["legacy-batch-prod"]) in _edges(r, "internet")
    assert r["stats"]["external"] >= 2


def test_access_endpoint():
    c = client()
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    r = c.post("/api/access", headers=H, json={"scan_id": scan_id, "filter": {"include": "prod"}})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] and body["filter"]
    assert all("prod" in a["name"] for a in body["accounts"])
    assert c.post("/api/access", headers=H, json={"scan_id": "nope"}).status_code == 404
    assert c.post("/api/access", json={"scan_id": scan_id}).status_code in (403, 400)  # no X-ExitRisk header


def test_ingress_sources_record_any_ipv6_address():
    groups = [{"GroupId": "sg-web", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "Ipv6Ranges": [{"CidrIpv6": "::/0"}, {"CidrIpv6": "2001:db8::/32"}]}]}]  # fmt: skip
    got = access.ingress_sources(groups, OWN, ["10.1.0.0/16"], in_use=None)
    assert got["cidrs"] == [{"cidr": "::/0", "ports": "tcp 443", "groups": ["sg-web"]}]
