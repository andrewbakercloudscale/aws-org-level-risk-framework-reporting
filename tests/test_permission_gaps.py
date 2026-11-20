"""A permission the scan role lacks never fails the scan and never reads as a pass, a zero or "not set up"."""

from botocore.exceptions import ClientError

from exitrisk import assurance, network_review, scanner, scoring, store
from exitrisk.collectors import assurance as checks
from exitrisk.collectors import assurance_org, healthcheck_deep
from exitrisk.scanner import ScanJob, ScanParams


def _denied(op="Call"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, op)


class FakeClient:
    """Answers the methods given; every other call is refused."""

    def __init__(self, answers=None):
        self.answers = answers or {}

    def can_paginate(self, _op):
        return False

    def __getattr__(self, name):
        if name in self.answers:
            a = self.answers[name]
            return a if callable(a) else (lambda **_kw: a)

        def refuse(**_kw):
            raise _denied(name)

        return refuse


class FakeSession:
    def __init__(self, clients=None):
        self.clients = clients or {}
        self.region_name = "eu-west-1"

    def client(self, name, region_name=None, config=None):
        return self.clients.get(name) or FakeClient()


def test_cost_explorer_refused_carries_on_and_leaves_exit_risk_unscored(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "123456789012", "arn": "arn:x"})

    def no_org(_s):
        raise ClientError({"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "no org"}}, "Describe")

    def refused(*_a, **_k):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "ce denied"}}, "GetCostAndUsage")

    monkeypatch.setattr(scanner.organizations, "describe_org", no_org)
    monkeypatch.setattr(scanner.cost, "fetch_costs", refused)
    monkeypatch.setattr(scanner.cost, "fetch_storage", lambda s, ids, services: [])
    monkeypatch.setattr(scanner.cost, "fetch_commitments", lambda s: [])
    monkeypatch.setattr(scanner.cost, "fetch_direct_connect", lambda s, _: [])
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda *_a, **_k: [])
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "partial" and doc["costs"] == []  # saved, not failed: the gap is named
    assert "ce denied" in doc["unavailable"]["costs"]
    assert any(i["category"] == "cost" and "not scored" in i["message"] for i in doc["issues"])
    s = scoring.build_report(doc)["summary"]
    assert s["score"] is None and s["rating"] == "n/a" and "ce denied" in s["spend_unavailable"]


def test_an_account_that_refused_every_check_is_not_measured_not_low():
    severity = {"a": "high", "b": "low"}
    points = {"critical": 40, "high": 15, "medium": 5, "low": 1}
    acct = {"id": "1", "name": "blind", "tags": {}}
    blind = assurance._score(acct, [{"id": "a", "status": "unknown"}, {"id": "b", "status": "unknown"}],
                             severity, points, False, True, False, [], {"1": 500.0})  # fmt: skip
    seen = assurance._score({"id": "2", "name": "seen", "tags": {}}, [{"id": "a", "status": "fail"}],
                            severity, points, False, True, False, [], {"2": 100.0})  # fmt: skip
    assert blind["rating"] == assurance.NOT_MEASURED and seen["rating"] != assurance.NOT_MEASURED
    s = assurance._summary([blind, seen], [])
    assert s["accounts"] == 2 and s["accounts_blind"] == 1
    assert s["score"] == seen["score"]  # the blind account's spend does not pull the score down to "low"
    assert s["monthly_spend"] == 600.0


def test_own_trail_status_refused_is_not_measured_but_org_trail_stays_a_pass():
    def run(org):
        trail = {"Name": "t", "TrailARN": "arn:t", "IsMultiRegionTrail": True, "HomeRegion": "eu-west-1",
                 "IsOrganizationTrail": org, "LogFileValidationEnabled": True}  # fmt: skip
        ct = FakeClient({"describe_trails": {"trailList": [trail]}})
        ctx = checks.Ctx(FakeSession({"cloudtrail": ct}), "111111111111", ["eu-west-1"], {})
        try:
            checks.task_cloudtrail(ctx)
        except ClientError:
            pass
        return ctx.r.finish()["cloudtrail_off"]["status"]

    assert run(False) == "unknown"
    assert run(True) == "pass"


def test_a_refused_deep_health_read_is_a_gap_and_other_errors_stay_quiet():
    class Ctx:
        def __init__(self):
            self.gaps = []

        def gap(self, region, check, exc):
            self.gaps.append((region, check))

    ctx = Ctx()
    with healthcheck_deep._refused(ctx, "eu-west-1", "EFS"):
        raise _denied("DescribeFileSystems")
    with healthcheck_deep._refused(ctx, "eu-west-1", "FSx"):
        raise ClientError({"Error": {"Code": "UnsupportedOperation", "Message": "x"}}, "DescribeFileSystems")
    assert ctx.gaps == [("eu-west-1", "EFS")]


def test_identity_center_refused_reads_as_not_read_not_absent():
    assert assurance_org.identity_center_region(FakeSession(), "eu-west-1") == (None, "AccessDenied")
    empty = FakeSession({"sso-admin": FakeClient({"list_instances": {"Instances": []}})})
    assert assurance_org.identity_center_region(empty, "eu-west-1") == (None, "")


def test_refused_flow_logs_count_as_denied_not_zero():
    nets, cov = [], {k: 0 for k in ("insights_bytes", "s3_only", "flows_read", "tcp_read", "baseline_read",
                                     "metrics_read", "baseline_full", "s3_accounts", "flows_denied",
                                     "flows_denied_regions")}  # fmt: skip
    f = {"access_flows": {"eu-west-1": {"refused": "AccessDenied", "rows": [], "rejected": []},
                          "us-east-1": {"reject_covered": ["vpc-1"], "rows": [], "rejected": []}}}  # fmt: skip
    who = network_review._Who({}, {}, {}, [])
    row = network_review._account("1", f, nets, who, None, network_review._Seen(), [], cov)
    assert row["read"]["denied"] == ["eu-west-1"] and row["read"]["flows"]
    assert cov["flows_denied"] == 1 and cov["flows_denied_regions"] == 1
