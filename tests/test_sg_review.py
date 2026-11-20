"""Security Group Review: planning, queries, rule history, the report and the API (no AWS, no network)."""

import json
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from exitrisk import demo_sg, ipintel, sg_review
from exitrisk.cidr_collapse import collapse_ips_to_cidrs
from exitrisk.collectors import sg_flows
from exitrisk.demo import build_demo_scan
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}
NOW = datetime(2026, 11, 20, 17, 30, tzinfo=timezone.utc).timestamp()


@pytest.fixture(scope="module")
def scan():
    return build_demo_scan(6)


def _acct(scan):
    return next(a["id"] for a in scan["accounts"] if sg_review.regions_of(scan, a["id"]))


# ------------------------------------------------------------------------------------------ planning
def test_plan_slices_hourly_six_hourly_daily_and_fills_only_the_gap():
    one = sg_review.plan(NOW, 1)
    assert all(e - s == 3600 for s, e in one)
    end = sg_review.read_end(NOW)
    assert max(e for _, e in one) == end and min(s for s, _ in one) % sg_review.SIX == 0
    week = sg_review.plan(NOW, 7)
    assert {e - s for s, e in week} == {3600, sg_review.SIX}
    month = sg_review.plan(NOW, 30)
    assert sg_review.DAY in {e - s for s, e in month}
    assert min(s for s, _ in month) % sg_review.DAY == 0
    # nothing left once read; a later read plans only the hours since
    assert sg_review.plan(NOW, 30, month) == []
    later = sg_review.plan(NOW + 3 * 3600, 30, month)
    assert sum(e - s for s, e in later) == 3 * 3600
    assert later == sorted(later, reverse=True)


def test_queries_filter_inbound_and_keep_refused_internet_sources_apart():
    fmt = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${flow-direction}"  # noqa: E501
    q = sg_flows.detail_query(fmt, ["10.0.0.0/16"])
    assert 'f_flow_direction = "ingress"' in q and "least(f_dstport, 32768)" in q and "limit 10000" in q
    assert 'f_action = "ACCEPT" or (isIpv4InSubnet(f_srcaddr, "10.0.0.0/8")' in q
    assert "least" not in sg_flows.detail_query(fmt, [], fold=False)
    p = sg_flows.public_query(None, ["10.0.0.0/16"])
    assert 'isIpv4InSubnet(f_dstaddr, "10.0.0.0/16")' in p and 'f_action = "REJECT" and not' in p
    assert sg_flows.detail_query("${version} ${srcaddr}", []) is None


def test_rule_history_event_parsing():
    ev = {"EventTime": datetime(2026, 11, 1, tzinfo=timezone.utc), "CloudTrailEvent": json.dumps({
        "eventName": "AuthorizeSecurityGroupIngress", "userIdentity": {"arn": "arn:aws:sts::1:assumed-role/r/alice"},
        "requestParameters": {"groupId": "sg-1", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}}})}  # fmt: skip  # noqa: E501
    p = sg_flows.parse_event(ev)
    assert p["group"] == "sg-1" and p["added"] == [["6", 443, 443, "10.0.0.0/8"]] and p["who"] == "alice"
    by_id = {"EventTime": ev["EventTime"], "CloudTrailEvent": json.dumps({
        "eventName": "RevokeSecurityGroupIngress",
        "requestParameters": {"groupId": "sg-1", "securityGroupRuleIds": {"items": ["sgr-1"]}}})}  # fmt: skip
    assert sg_flows.parse_event(by_id)["unknown"]
    failed = {"CloudTrailEvent": json.dumps({"eventName": "AuthorizeSecurityGroupIngress", "errorCode": "Denied"})}
    assert sg_flows.parse_event(failed) is None


def test_state_at_works_back_through_changes():
    now = {("6", 22, 22, "10.200.0.0/16")}
    evs = [{"t": 100, "unknown": False, "added": [["6", 22, 22, "10.200.0.0/16"]], "removed": []},
           {"t": 101, "unknown": False, "added": [], "removed": [["6", 22, 22, "10.0.0.0/8"]]}]  # fmt: skip
    assert sg_review._state_at(now, evs, 200) == (now, True)
    assert sg_review._state_at(now, evs, 50) == ({("6", 22, 22, "10.0.0.0/8")}, True)
    state, known = sg_review._state_at(now, [{"t": 100, "unknown": True, "added": [], "removed": []}], 50)
    assert state == now and not known


def test_collapse_keeps_every_address_and_never_widens_public():
    out = collapse_ips_to_cidrs([f"10.0.1.{i}" for i in range(1, 250)] + ["8.8.8.8"])
    assert out == ["8.8.8.8/32", "10.0.1.0/24"]


def test_intervals():
    a = [ipintel.cidr_iv("10.0.0.0/8")]
    b = [ipintel.cidr_iv("10.1.0.0/16")]
    assert ipintel.size(ipintel.subtract(a, b)) == 2**24 - 2**16
    assert ipintel.intersect(a, b) == b


# ------------------------------------------------------------------------------------------- report
@pytest.fixture(scope="module")
def report(scan):
    doc = demo_sg.build_doc(scan, _acct(scan), time.time(), 90)
    return doc, sg_review.build(doc, scan, "3m", "")


def test_over_provisioned_never_counts_a_seen_address(report, scan):
    doc, rep = report
    seen = set()
    for c in doc["chunks"]:
        seen |= {r[0] for r in c["rows"]} | {r[0] for r in c["pub"]}
    ivs = ipintel.merge([(n, n) for n in map(sg_review._ip, seen)])
    for r in rep["rules"]:
        allowed = ipintel.merge([ipintel.cidr_iv(r["source"])])
        assert r["never"] == ipintel.size(ipintel.subtract(allowed, ivs))
    assert rep["summary"]["over_now"] > 0
    assert all(v >= 0 for s in rep["series"]["over"].values() for v in s)


def test_rule_changes_move_the_over_provisioned_line(report):
    _, rep = report
    total = [sum(rep["series"]["over"][k][i] for k in sg_review.CATS) for i in range(len(rep["bins"]))]
    assert len(set(total)) >= 3  # the revoke, the tightening, then the wide batch rule added back
    assert {m["event"] for m in rep["markers"]} >= {"AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"}


def test_rules_statuses_and_suggestions(report):
    _, rep = report
    by = {(r["gname"], r["source"]): r for r in rep["rules"]}
    assert by[("public-alb", "0.0.0.0/0")]["status"] == "open"
    assert by[("payments-db", "172.16.0.0/12")]["status"] == "unused"
    db = next(r for (g, s), r in by.items() if g == "payments-db" and s != "172.16.0.0/12")
    assert db["status"] == "tighten" and db["suggest"]
    # the suggestion keeps every address seen on the group, the DR replica included
    sugg = ipintel.merge([ipintel.cidr_iv(c) for c in db["suggest"]])
    for x in db["top"]:
        n = sg_review._ip(x["src"])
        assert any(a <= n <= b for a, b in sugg)
    assert by[("partner-sftp", "203.0.113.0/24")]["status"] == "tighten"


def test_sources_are_labelled_and_dr_shows_apart(report):
    _, rep = report
    cats = {x["cat"] for x in rep["refused"]}
    assert {"datacentre", "aws", "saas", "internet"} <= cats
    acl = next(x for x in rep["refused"] if x["src"] == "10.200.9.9")
    assert acl["name"] == "Behind VPN Johannesburg DC" and acl["targets"][0]["by"].startswith("Network ACL")
    assert any(x["cat"] == "aws" and "Route 53" in x["name"] for x in rep["refused"])
    assert any(x["sweep"] for x in rep["refused"])
    assert rep["suggestions"] and rep["suggestions"][0]["cidrs"]
    older = [x for x in rep["active"] if not x["today"]]
    assert older and any(x["days"] <= 3 for x in older)
    assert sum(rep["series"]["active_older"]["internal"]) > 0
    # replies to the account's own connections never count as active
    assert not any(x["src"] == "52.95.110.1" for x in rep["active"])


def test_short_evidence_is_never_called_unused(scan):
    doc = demo_sg.build_doc(scan, _acct(scan), time.time(), 1)
    rep = sg_review.build(doc, scan, "24h", "")
    assert not any(r["status"] in ("unused", "tighten") for r in rep["rules"])
    assert rep["summary"]["watch"] > 0


def test_approved_json_is_sg_tightener_v2(report):
    doc, _ = report
    region = next(iter(doc["regions"]))
    a = sg_review.approved(doc, region)
    assert a["schema"] == "sg-tightener.approved/v2" and a["ips"] and a["flows"]
    assert all(f["dstport"] < 32768 for f in a["flows"])


# ------------------------------------------------------------------------------------------------ API
def test_api_demo_read_report_and_download():
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    sid = c.post("/api/scans/demo", headers=H).json()["id"]
    accts = c.post("/api/sg/accounts", json={"scan_id": sid}, headers=H).json()["accounts"]
    acct = next(a["id"] for a in accts if a["regions"])
    rep = c.post("/api/sg/report", json={"scan_id": sid, "account": acct}, headers=H).json()
    assert rep["empty"] and rep["estimate"]["rate"] is None
    job = c.post("/api/sg/read", json={"scan_id": sid, "account": acct, "days": 7}, headers=H).json()
    assert job["status"] == "done"
    rep = c.post("/api/sg/report", json={"scan_id": sid, "account": acct, "range": "1w"}, headers=H).json()
    assert len(rep["bins"]) >= 28 and rep["estimate"]["rate"] > 0
    assert rep["estimate"]["ranges"][1]["missing_hours"] == 0 and rep["estimate"]["ranges"][2]["cost"] > 0
    region = next(iter(rep["regions"]))
    r = c.get(f"/api/sg/approved/{acct}?region={region}")
    assert r.status_code == 200 and r.json()["schema"] == "sg-tightener.approved/v2"
    assert c.post("/api/sg/read", json={"scan_id": sid, "account": acct, "days": 5}, headers=H).status_code == 400
    assert (
        c.post("/api/sg/read", json={"scan_id": sid, "account": "000000000000", "days": 1}, headers=H).status_code
        == 400
    )
    assert c.get("/api/health").json()["sg_reads_running"] == []
    assert c.delete(f"/api/sg/data/{acct}", headers=H).json()["deleted"]


class _FakeLogs:
    """Logs Insights stand-in: a slice longer than an hour fills the row limit; an hour does not."""

    def __init__(self):
        self.q = {}
        self.calls = []

    def start_query(self, **kw):
        qid = f"q{len(self.q)}"
        self.q[qid] = kw
        self.calls.append((kw["endTime"] + 1 - kw["startTime"], "stats count(*) as flows, sum" in kw["queryString"]))
        return {"queryId": qid}

    def get_query_results(self, queryId):
        kw = self.q[queryId]
        span = kw["endTime"] + 1 - kw["startTime"]
        detail = "sum(f_bytes)" in kw["queryString"]
        n = sg_flows.ROWS if detail and span > 3600 else 2
        row = [{"field": "src", "value": "10.0.0.5"}, {"field": "dst", "value": "10.0.1.1"},
               {"field": "eni", "value": "eni-1"}, {"field": "proto", "value": "6"},
               {"field": "dport", "value": "443"}, {"field": "port", "value": "443"},
               {"field": "action", "value": "ACCEPT"}, {"field": "flows", "value": "3"}]  # fmt: skip
        return {"status": "Complete", "statistics": {"bytesScanned": 1000.0}, "results": [row] * n}


def test_read_chunk_splits_a_full_slice_down_to_hours():
    logs = _FakeLogs()
    start = 1_790_000_000 // 3600 * 3600
    out = sg_review.read_chunk(logs, "eu-west-1", start, start + 4 * 3600, [{"format": None, "groups": ["g"]}], [])
    assert sorted(c["e"] - c["s"] for c in out) == [3600] * 4
    assert all(c["st"] == "ok" and len(c["rows"]) == 2 for c in out)
    assert sum(c["b"] for c in out) > 0
