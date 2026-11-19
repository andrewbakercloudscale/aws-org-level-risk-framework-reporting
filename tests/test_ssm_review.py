"""SSM Abuse Review: who drove SSM, who could, and the demo's story."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from exitrisk.collectors import ssm_abuse as sa
from exitrisk.demo import build_demo_scan
from exitrisk.network_review import build_network_review
from exitrisk.ssm_review import build_ssm_review

ACCT = "111111111111"
NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)


def _ev(ident: dict, ip: str = "196.25.1.17", **extra) -> dict:
    return {"userIdentity": ident, "sourceIPAddress": ip, **extra}


def test_callers_are_told_apart():
    org = {"222222222222"}
    role = lambda r, s, a=ACCT: {"type": "AssumedRole", "accountId": a, "arn": f"arn:aws:sts::{a}:assumed-role/{r}/{s}"}  # noqa: E731
    assert sa.caller(_ev(role("ops", "x"), ip="ssm.amazonaws.com"), ACCT, org)["kind"] == "service"
    assert sa.caller(_ev({**role("maint", "x"), "invokedBy": "ssm.amazonaws.com"}), ACCT, org)["kind"] == "service"
    assert sa.caller(_ev(role("AWSReservedSSO_Ops_abc123", "pat@example.com")), ACCT, org)["kind"] == "person"
    assert sa.caller(_ev(role("ci-runner", "i-0123456789abcdef0")), ACCT, org)["kind"] == "server"
    assert sa.caller(_ev(role("hybrid", "mi-0123456789abcdef0")), ACCT, org)["kind"] == "server"
    assert sa.caller(_ev(role("deploy", "x", "333333333333")), ACCT, org)["kind"] == "outside"
    assert sa.caller(_ev(role("deploy", "x", "222222222222")), ACCT, org)["kind"] == "automation"
    key = sa.caller(_ev({"type": "IAMUser", "accountId": ACCT, "userName": "bot", "arn": "arn:aws:iam::1:user/bot"}),
                    ACCT, org)  # fmt: skip
    assert key == {"kind": "key", "who": "IAM user bot", "account": ACCT}
    assert sa.caller(_ev({"type": "Root", "accountId": ACCT}), ACCT, org)["kind"] == "root"


FULL = {"Statement": [{"Effect": "Allow", "Action": ["ssm:*"], "Resource": "*"},
                      {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}  # fmt: skip


def test_powers_read_policies_strictly():
    assert sa.powers([FULL], None, ACCT, "eu-west-1") == ["run", "onprem", "session", "params"]
    core = {"Statement": [{"Effect": "Allow", "Action": ["ssm:UpdateInstanceInformation", "ssmmessages:*"],
                           "Resource": "*"}]}  # fmt: skip
    assert sa.powers([core], None, ACCT, "eu-west-1") == []
    tagged = {"Statement": [{"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": "*",
                             "Condition": {"StringEquals": {"ssm:resourceTag/team": "web"}}}]}  # fmt: skip
    assert sa.powers([tagged], None, ACCT, "eu-west-1") == []  # narrowed by a tag: not every server
    deny = {"Statement": [{"Effect": "Deny", "Action": "ssm:StartSession", "Resource": "*",
                           "Condition": {"Bool": {"aws:ViaAWSService": "false"}}}]}  # fmt: skip
    assert "session" not in sa.powers([FULL, deny], None, ACCT, "eu-west-1")
    boundary = {"Statement": [{"Effect": "Allow", "Action": "ssm:GetParameter*", "Resource": "*"}]}
    assert sa.powers([FULL], boundary, ACCT, "eu-west-1") == ["params"]
    one_doc = {"Statement": [{"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": [
        "arn:aws:ec2:*:*:instance/*", "arn:aws:ssm:*::document/AWS-RunPatchBaseline"]}]}  # fmt: skip
    assert sa.powers([one_doc], None, ACCT, "eu-west-1") == []  # patching only: no shell
    assert sa.read_named("permission set CTO-Read") and sa.read_named("role app-readonly-role")
    assert not sa.read_named("permission set ThreadOps")


def test_node_summary_counts_hybrid_servers():
    infos = [{"InstanceId": "i-1", "ResourceType": "EC2Instance"},
             {"InstanceId": "mi-1", "ResourceType": "ManagedInstance", "PingStatus": "Online",
              "PlatformType": "Windows",
              "IamRole": "HybridRole", "RegistrationDate": datetime(2026, 11, 10, tzinfo=timezone.utc),
              "ComputerName": "DC1", "IPAddress": "10.1.1.1"},
             {"InstanceId": "mi-2", "ResourceType": "ManagedInstance", "PingStatus": "ConnectionLost",
              "PlatformType": "Linux", "IamRole": "HybridRole", "RegistrationDate": datetime(2025, 1, 1)}]  # fmt: skip
    n = sa.node_summary(infos, NOW)
    assert (n["ec2"], n["hybrid"], n["hybrid_online"]) == (1, 2, 1)
    assert n["roles"] == {"HybridRole": 2} and n["new_count"] == 1 and n["new"][0]["name"] == "DC1"


class _CT:
    def __init__(self, events: dict):
        self.events = events

    def get_paginator(self, _op):
        ct = self

        class P:
            def paginate(self, LookupAttributes, **_kw):  # noqa: N803
                name = LookupAttributes[0]["AttributeValue"]
                return iter([{"Events": [{"CloudTrailEvent": json.dumps(e)} for e in ct.events.get(name, [])]}])

        return P()


def test_activity_leaves_out_ssm_itself_and_keeps_who_and_what():
    key = {"type": "IAMUser", "accountId": ACCT, "userName": "bot"}
    events = {
        "SendCommand": [
            {"userIdentity": {"type": "AssumedRole", "invokedBy": "ssm.amazonaws.com", "accountId": ACCT},
             "sourceIPAddress": "ssm.amazonaws.com", "requestParameters": {"documentName": "AWS-RunPatchBaseline"}},
            {"userIdentity": key, "sourceIPAddress": "45.83.64.11", "eventTime": "2026-11-16T22:41:00Z",
             "requestParameters": {"documentName": "AWS-RunShellScript", "instanceIds": ["i-1", "i-2"]}},
            {"userIdentity": key, "sourceIPAddress": "45.83.64.11", "eventTime": "2026-11-15T22:41:00Z",
             "requestParameters": {"documentName": "AWS-RunShellScript", "instanceIds": ["i-3"]}},
        ],
        "StartSession": [{"userIdentity": key, "sourceIPAddress": "45.83.64.11", "errorCode": "AccessDenied",
                          "requestParameters": {"target": "i-9"}}],
    }  # fmt: skip
    a = sa.read_activity(_CT(events), ACCT, set(), NOW)
    assert a["events"]["SendCommand"] == {"n": 3, "service": 1, "cut": False}
    run = next(r for r in a["rows"] if r["call"] == "SendCommand")
    assert (run["kind"], run["n"], run["servers"], run["where"]) == ("key", 2, 2, "internet")
    assert run["first"] < run["last"]
    refused = next(r for r in a["rows"] if r["call"] == "StartSession")
    assert refused["code"] == "AccessDenied" and refused["aims"] == ["i-9"]


def test_review_of_the_demo_names_the_stories_and_nothing_else():
    r = build_ssm_review(build_demo_scan(6))
    assert r["available"]
    look = {a["name"]: a for a in r["look"]}
    assert set(look) == {"legacy-batch-prod", "digital-channels-prod", "payments-core-prod", "shared-network-prod"}
    legacy = [x["text"] for x in look["legacy-batch-prod"]["reasons"]]
    assert any(t.startswith("An IAM user's access key ran commands") for t in legacy)
    assert any(t.startswith("Refused: an IAM user's access key") for t in legacy)
    assert any("tunnelled through a server" in x["text"] for x in look["digital-channels-prod"]["reasons"])
    assert look["shared-network-prod"]["reasons"][0]["kind"] == "exposure"
    assert r["totals"]["pivot_servers"] == 3 and r["totals"]["hybrid"] == 140
    # everyday sessions by people are counted, not listed
    assert all(x["kind"] != "person" or x["every"] for x in r["activity"])
    assert r["routine"]["lines"] > 0


def test_a_scan_from_before_the_review_says_so():
    scan = build_demo_scan(6)
    for res in scan["assurance"]["accounts"].values():
        res["facts"].pop("ssm_abuse", None)
        res["facts"].pop("ssm_holders", None)
    r = build_ssm_review(scan)
    assert not r["available"] and "before the SSM Abuse Review" in r["reason"]


def test_internet_traffic_by_account():
    from exitrisk.collectors.access import _add_internet, internet_query

    q = internet_query("${srcaddr} ${dstaddr} ${dstport} ${bytes} ${action}")
    assert 'isIpv4InSubnet(f_srcaddr, "10.0.0.0/8")' in q and "count_distinct(f_dstaddr) as dsts" in q
    out: dict = {}
    _add_internet(out, [{"src_private": "1", "dst_private": "0", "bytes": "500", "flows": "5", "dsts": "7"},
                        {"src_private": "0", "dst_private": "1", "bytes": "900", "flows": "9", "srcs": "3"},
                        {"src_private": "1", "dst_private": "1", "bytes": "100000", "flows": "1"}])  # fmt: skip
    assert out["internet"] == {"out": {"bytes": 500, "flows": 5, "ips": 7}, "in": {"bytes": 900, "flows": 9, "ips": 3}}
    r = build_network_review(build_demo_scan(6))
    by = {a["name"]: a for a in r["internet"]}
    assert by["digital-channels-prod"]["exact"] and by["digital-channels-prod"]["ips"] == 140
    assert by["digital-channels-prod"]["bytes"] == by["digital-channels-prod"]["out_bytes"] + by[
        "digital-channels-prod"]["in_bytes"]  # fmt: skip
    assert by["digital-channels-prod"]["top"][0]["ip"] == "151.101.1.69"
