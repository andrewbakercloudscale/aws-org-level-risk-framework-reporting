"""Accepted risks: a rule names a fleet by name or tag; what it covers leaves the counts until review or worse."""

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from exitrisk import accepted
from exitrisk.demo import build_demo_scan
from exitrisk.outage import build_outage, findings_csv
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}
SOON = (date.today() + timedelta(days=90)).isoformat()


def rule(**kw):
    base = {"id": "r1", "resource": "", "tag": "", "checks": [], "account": "", "reason": "by design",
            "accepted_by": "Platform", "review_on": SOON, "ceiling_pct": None, "ceiling_severity": None}  # fmt: skip
    return {**base, **kw}


def finding(**kw):
    base = {"rule": "ec2_cpu", "res": "prophet-01 (i-0abc)", "account": "pay-prod", "severity": "high", "pct": 100.0}
    return {**base, **kw}


def test_a_name_pattern_matches_a_fleet_and_text_alone_matches_names_containing_it():
    assert accepted.matches(rule(resource="prophet*"), finding())
    assert accepted.matches(rule(resource="PROPHET"), finding(res="batch-prophet-07 (i-1)"))
    assert not accepted.matches(rule(resource="prophet*"), finding(res="batch-prophet-07 (i-1)"))
    assert not accepted.matches(rule(resource="prophet*", checks=["rds_cpu"]), finding())
    assert not accepted.matches(rule(resource="prophet*", account="*-npr"), finding())


def test_a_tag_matches_by_key_and_value_ignoring_case_and_a_finding_without_tags_never_matches():
    tagged = finding(tags={"Risk-Accepted": "True"})
    assert accepted.matches(rule(tag="risk-accepted=true"), tagged)
    assert accepted.matches(rule(tag="risk-accepted"), tagged)
    assert not accepted.matches(rule(tag="risk-accepted=false"), tagged)
    assert not accepted.matches(rule(tag="risk-accepted"), finding())


def test_an_accepted_finding_comes_back_on_its_review_date_or_when_its_reading_is_worse():
    r = rule(resource="prophet*", ceiling_pct=100.0, ceiling_severity="high")
    kept, taken = accepted.judge([finding()], [r])
    assert not kept and taken[0]["accepted"]["reason"] == "by design"
    kept, taken = accepted.judge([finding(severity="critical")], [r])
    assert not taken and "now critical" in kept[0]["accepted_lapsed"]["why"]
    r2 = rule(resource="disk", ceiling_pct=80.0)
    kept, _ = accepted.judge([finding(res="disk-01", pct=91.0)], [r2])
    assert "above the 80% accepted" in kept[0]["accepted_lapsed"]["why"]
    kept, _ = accepted.judge([finding()], [r], today=date.today() + timedelta(days=91))
    assert "review was due" in kept[0]["accepted_lapsed"]["why"]


def test_a_rule_must_name_resources_and_be_reviewed_within_a_year():
    ok = {"reason": "by design", "accepted_by": "Platform", "review_on": SOON}
    with pytest.raises(ValueError):
        accepted.AcceptedRule(**ok)
    with pytest.raises(ValueError):
        accepted.AcceptedRule(resource="*", **ok)
    with pytest.raises(ValueError):
        accepted.AcceptedRule(
            resource="prophet", **{**ok, "review_on": (date.today() + timedelta(days=400)).isoformat()}
        )
    with pytest.raises(ValueError):
        accepted.AcceptedRule(resource="prophet", **{**ok, "review_on": date.today().isoformat()})


def test_accepted_findings_leave_the_counts_and_actions_and_are_listed_apart():
    scan = build_demo_scan(6)
    before = build_outage(scan, taken=[])
    f = next(x for x in before["findings"] if x["severity"] in ("critical", "high") and x["production"])
    r = rule(resource=f["res"], checks=[f["rule"]], account=f["account"], ceiling_pct=f["pct"],
             ceiling_severity=f["severity"])  # fmt: skip
    after = build_outage(scan, taken=[r])
    assert (
        after["accepted_total"] >= 1 and after["findings_total"] == before["findings_total"] - after["accepted_total"]
    )
    assert all(not accepted.matches(r, x) for x in after["findings"])
    acct = next(a for a in after["accounts"] if a["id"] == f["account_id"])
    assert acct["accepted"] >= 1
    assert all(not (x["res"] == f["res"] and x["rule"] == f["rule"] and x["account"] == f["account"])
               for x in after["immediate"]["rows"])  # fmt: skip
    assert after["accepted_rules"][0]["covers"] == after["accepted_total"]
    text = findings_csv(after)
    assert len(text.strip().splitlines()) == len(after["findings"]) + len(after["accepted"]) + 1
    assert "accepted by Platform until" in text


def test_accepted_risk_api_counts_what_a_rule_covers_saves_it_and_removes_it():
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    report = c.post("/api/outage", headers=H, json={"scan_id": scan_id}).json()
    f = report["findings"][0]
    body = {"scan_id": scan_id, "rule": {"resource": f["res"], "checks": [f["rule"]], "reason": "by design",
                                         "accepted_by": "Platform", "review_on": SOON}}  # fmt: skip
    try:
        p = c.post("/api/accepted/preview", headers=H, json=body).json()
        assert p["covers"] >= 1 and p["examples"][0]["res"] == f["res"]
        nothing = {**body, "rule": {**body["rule"], "resource": "no-such-server-anywhere"}}
        assert c.post("/api/accepted", headers=H, json=nothing).status_code == 400
        saved = c.post("/api/accepted", headers=H, json=body).json()
        assert saved["id"] and saved["ceiling_severity"] == f["severity"]
        again = c.post("/api/outage", headers=H, json={"scan_id": scan_id}).json()
        assert again["accepted_total"] == p["covers"]
        assert again["findings_total"] == report["findings_total"] - p["covers"]
        assert c.get("/api/accepted").json()["rules"][0]["id"] == saved["id"]
    finally:
        for x in c.get("/api/accepted").json()["rules"]:
            assert c.delete(f"/api/accepted/{x['id']}", headers=H).status_code == 200
    assert c.post("/api/outage", headers=H, json={"scan_id": scan_id}).json()["accepted_total"] == 0


def test_the_collector_keeps_a_servers_own_tags_on_its_findings_and_leaves_out_aws_ones():
    from exitrisk.collectors import outage as collector

    ctx = collector.OutageCtx(None, "111111111111", ["af-south-1"], {})
    ctx.tag("af-south-1", "prophet-01 (i-1)", {"risk-accepted": "true", "aws:autoscaling:groupName": "x"})
    ctx.add("ec2_cpu", "prophet-01 (i-1)", "af-south-1", pct=100.0)
    ctx.add("ec2_cpu", "other (i-2)", "af-south-1", pct=100.0)
    assert ctx.rows[0]["tags"] == {"risk-accepted": "true"} and "tags" not in ctx.rows[1]
