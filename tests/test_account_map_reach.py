"""Account map: data centre and other outside ranges, S3 bucket access, Lambda reach, refused traffic and
traffic in and out."""

import json

from exitrisk.account_map import build_account_map, parse_ranges
from exitrisk.collectors import access
from exitrisk.demo import build_demo_scan

OWN = "111111111111"


def _demo(name: str, onprem: str = "") -> dict:
    scan = build_demo_scan()
    aid = next(a["id"] for a in scan["accounts"] if a["name"].startswith(name))
    return build_account_map(scan, aid, onprem=onprem)


# ---------------------------------------------------------------------------------- policies


def _policy(*statements) -> str:
    return json.dumps({"Statement": list(statements)})


def test_a_deny_unless_from_an_endpoint_holds_the_bucket_to_it():
    deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:SourceVpce": ["vpce-1", "vpce-2"]},
                          "NotIpAddress": {"aws:SourceIp": "196.25.1.0/24"}}}  # fmt: skip
    assert access.policy_limits(_policy(deny)) == {"ip": ["196.25.1.0/24"], "vpce": ["vpce-1", "vpce-2"]}


def test_conditions_that_do_not_hold_every_request_are_not_limits():
    allow = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
             "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}  # fmt: skip
    deny_writes = {"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
                   "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}}  # fmt: skip
    deny_from = {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                 "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}  # fmt: skip
    one_role = {"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{OWN}:role/x"}, "Action": "*",
                "Condition": {"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}}  # fmt: skip
    assert access.policy_limits(_policy(allow, deny_writes, deny_from, one_role)) == {}


def test_parse_ranges():
    got = parse_ranges("10.200.0.0/16 Johannesburg DC,\n172.20.0.0/14, nonsense, 0.0.0.0/0 everything")
    assert [(str(n), label) for n, label in got] == [
        ("10.200.0.0/16", "Johannesburg DC"), ("172.20.0.0/14", "On-premises 172.20.0.0/14")]  # fmt: skip


def test_flow_query_for_refused_traffic_sorts_by_attempts():
    q = access.flow_query("", "REJECT")
    assert 'f_action = "REJECT"' in q and "sort flows desc" in q
    assert "sort bytes desc" in access.flow_query("")


# ---------------------------------------------------------------------------------- the map


def test_data_centre_ranges_from_routes_and_security_groups():
    r = _demo("payments-core-prod", "172.16.0.0/12 Johannesburg DC")
    rows = {x["cidr"]: x for x in r["ranges"]}
    assert rows["172.16.0.0/12"]["named"] and rows["172.16.0.0/12"]["label"] == "Johannesburg DC"
    assert any("routed to Transit gateway" in h for h in rows["172.16.0.0/12"]["how"])
    assert rows["172.16.20.0/24"]["label"] == "Johannesburg DC"
    assert any("admitted on tcp 443" in h for h in rows["172.16.20.0/24"]["how"])
    # the own VPC's ranges and the 10.0.0.0/8 that spans the organisation are not outside networks
    assert "10.0.0.0/8" not in rows
    links = {(x["from"], x["to"]) for x in r["links"]}
    assert ("tgw:tgw-0demo", "onprem:range:172.16.0.0/12") in links
    # without a name the same range is "other private networks"
    r = _demo("payments-core-prod")
    assert {x["cidr"]: x["label"] for x in r["ranges"]}["172.16.0.0/12"] == "Other private networks"


def test_vpn_static_routes_name_the_data_centre():
    r = _demo("legacy-batch")
    rows = {x["cidr"]: x for x in r["ranges"]}
    assert rows["192.168.0.0/16"]["label"] == "Johannesburg data centre"
    assert any("static route on vpn-0datacentre" in h for h in rows["192.168.0.0/16"]["how"])


def test_every_bucket_with_its_access():
    r = _demo("data-platform-prod")
    b = r["buckets"]
    assert b and all(x["access"] == "outside" and x["who"] for x in b)
    node = next(n for n in r["nodes"] if n["kind"] == "bucket")
    assert node["label"].endswith(("S3 bucket", "S3 buckets"))
    pay = _demo("payments-core-prod")["buckets"]
    settle = next(x for x in pay if "settlement" in x["name"])
    assert settle["access"] == "account" and settle["limits"] == {"vpce": ["vpce-s3589175"]}


def test_lambda_reach_internet_data_centre_and_open_urls():
    r = _demo("payments-core-prod", "172.16.0.0/12 Johannesburg DC")
    fns = {f["name"]: f for f in r["lambdas"]}
    events, worker = fns["payments-core-events"], fns["payments-core-worker"]
    assert events["internet"] == "yes" and not events["networks"]
    assert worker["internet"] == "central"  # the default route goes to the transit gateway
    assert [n["label"] for n in worker["networks"]] == ["Johannesburg DC"]
    legacy = {f["name"]: f for f in _demo("legacy-batch")["lambdas"]}["legacy-batch-worker"]
    assert legacy["internet"] == "yes" and "NAT gateway" in legacy["internet_via"]
    assert "Johannesburg data centre" in [n["label"] for n in legacy["networks"]]
    digital = _demo("digital-channels-prod")
    assert any(f["url"] == "NONE" for f in digital["lambdas"])
    node = next(n for n in digital["nodes"] if n["kind"] == "lambda")
    assert "function URL open to anyone" in node["flags"]


def test_lambdas_unread_say_so():
    scan = build_demo_scan()
    for res in scan["assurance"]["accounts"].values():
        for x in (res.get("facts") or {}).get("access_assets", {}).values():
            x.pop("lambdas", None)
    aid = next(a["id"] for a in scan["accounts"] if a["name"].startswith("payments-core-prod"))
    assert build_account_map(scan, aid)["lambdas"] is None


def test_traffic_in_and_out_and_refused_traffic():
    f = _demo("payments-core-prod")["flows"]
    assert f["bytes_in"] + f["bytes_out"] == f["attributed_bytes"]
    assert all(t["bytes"] == t["bytes_in"] + t["bytes_out"] for t in f["top"])
    rf = f["refused"]
    assert rf["flows"] == rf["in"] + rf["out"] and rf["from_internet"] >= 10_000
    assert rf["top"][0]["port"] == "22" and rf["top"][0]["dir"] == "in"
    links = _demo("digital-channels-prod")["links"]
    assert any(x["rejected"] and x["to"] == "internet" for x in links)
