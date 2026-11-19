"""Network Traffic Review: the flow-log queries for failed TCP and the week before, what is new today, and the
review built from them, account by account."""

from test_server import H, client

from exitrisk.collectors import access
from exitrisk.demo import build_demo_scan
from exitrisk.network_review import build_network_review, port_name

V3 = ("${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} "
      "${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${tcp-flags}")  # fmt: skip


def test_tcp_query_needs_the_tcp_flags_and_counts_retried_syns_and_resets():
    assert access.tcp_query(access.DEFAULT_FORMAT) is None
    q = access.tcp_query(V3)
    assert 'f_tcp_flags = "2" and f_packets >= 3' in q
    assert 'f_tcp_flags = "4" and f_packets <= 2' in q
    assert 'f_protocol = "6"' in q and 'f_action = "ACCEPT"' in q


def test_baseline_query_takes_refusals_and_with_flags_the_failed_tcp_too():
    plain = access.baseline_query(access.DEFAULT_FORMAT)
    assert 'f_action = "REJECT"' in plain and "tcp_flags" not in plain
    assert f"limit {access.BASE_ROWS}" in plain
    assert 'f_tcp_flags = "2"' in access.baseline_query(V3)
    assert access.baseline_query("${version} ${srcaddr}") is None


class _Logs:
    """Logs Insights answering every query with the same rows."""

    def __init__(self, rows, status="Complete"):
        self.rows, self.status, self.asked = rows, status, []

    def start_query(self, **kw):
        self.asked.append(kw)
        return {"queryId": "q"}

    def get_query_results(self, queryId):  # noqa: N803
        res = [[{"field": k, "value": v} for k, v in r.items()] for r in self.rows]
        return {"status": self.status, "results": res, "statistics": {"bytesScanned": 2e9}}


def _out():
    return {"rejected": [{"src": "1.2.3.4", "dst": "10.0.0.5", "port": "22", "flows": 9},
                         {"src": "5.6.7.8", "dst": "10.0.0.5", "port": "22", "flows": 4}],
            "failed_tcp": [{"src": "10.0.0.5", "dst": "10.9.0.1", "port": "1521", "kind": "unanswered",
                            "flows": 3}]}  # fmt: skip


REJECTS = {access.DEFAULT_FORMAT: {"groups": {"flows"}, "resources": {"vpc-1"}}}


def test_new_today_marks_pairs_and_sources_the_week_before_did_not_have():
    out, stats = _out(), {}
    logs = _Logs([{"src": "1.2.3.4", "dst": "10.0.0.5", "flows": "40"}, {"src": "10.0.0.5", "dst": "10.8.0.1"}])
    access._new_today(out, REJECTS, logs, 1_000_000, stats)
    assert out["baseline"] == {"days": access.BASE_DAYS, "read": True, "full": False, "pairs": 2}
    old, fresh = out["rejected"]
    assert old["new"] is False and old["src_new"] is False
    assert fresh["new"] is True and fresh["src_new"] is True
    tcp = out["failed_tcp"][0]
    assert tcp["new"] is True and tcp["src_new"] is False  # the source failed before, to another target
    assert logs.asked[0]["startTime"] == 1_000_000 - access.BASE_DAYS * 86400 and logs.asked[0]["endTime"] == 1_000_000
    assert stats["bytes"] == 2_000_000_000


def test_new_today_marks_nothing_when_the_week_before_is_too_large_or_unread():
    out = _out()
    full = _Logs([{"src": f"10.1.{i // 250}.{i % 250}", "dst": "10.0.0.5"} for i in range(access.BASE_ROWS)])
    access._new_today(out, REJECTS, full, 1_000_000, {})
    assert out["baseline"]["full"] and not out["baseline"]["read"]
    assert all("new" not in r for r in out["rejected"] + out["failed_tcp"])
    out = _out()
    access._new_today(out, REJECTS, _Logs([], status="Failed"), 1_000_000, {})
    assert out["baseline"] == {"days": access.BASE_DAYS, "read": False}
    assert all("new" not in r for r in out["rejected"])


def _scan():
    """Two accounts: A owns 10.0.0.0/16, B owns 10.1.0.0/16; 10.200.x is no one's (on premises)."""

    def facts(cidr, flows):
        return {"access_assets": {"eu-west-1": {"vpcs": [{"id": "vpc-1", "cidrs": [cidr]}]}},
                "access_flows": {"eu-west-1": flows}}  # fmt: skip

    a = {"reject_covered": ["vpc-1"], "tcp_covered": ["vpc-1"], "insights_bytes": 4e9,
         "baseline": {"days": 7, "read": True, "full": False, "pairs": 3},
         "rejected": [
             {"src": "45.33.1.9", "dst": "10.0.0.5", "port": p, "flows": 10, "bytes": 600, "new": False}
             for p in ("22", "23", "3389", "445", "1433")
         ] + [
             {"src": "10.1.0.7", "dst": "10.0.0.5", "port": "5432", "flows": 6, "bytes": 360, "new": True},
             {"src": "10.0.0.5", "dst": "10.200.1.1", "port": "1521", "flows": 4, "bytes": 240, "new": False},
             {"src": "10.0.0.5", "dst": "10.0.0.6", "port": "8080", "flows": 2, "bytes": 120, "new": False},
         ],
         "failed_tcp": [
             {"src": "10.0.0.5", "dst": "52.1.2.3", "port": "443", "kind": "unanswered", "flows": 5,
              "bytes": 300, "new": True, "src_new": False},
         ] + [
             {"src": "10.1.0.9", "dst": "10.0.0.6", "port": str(p), "kind": "reset", "flows": 1, "bytes": 40}
             for p in range(1000, 1012)
         ]}  # fmt: skip
    b = {"reject_covered": [], "s3_only": ["vpc-2"]}
    return {"id": "s1", "accounts": [{"id": "111111111111", "name": "alpha-prod"},
                                     {"id": "222222222222", "name": "beta-prod"}],
            "assurance": {"accounts": {
                "111111111111": {"facts": facts("10.0.0.0/16", a), "checks": {}},
                "222222222222": {"facts": facts("10.1.0.0/16", b),
                                 "checks": {"flow_logs": {"status": "fail", "n": 2}}},
            }}}  # fmt: skip


def test_review_classifies_where_each_failure_was_going_and_what_kind():
    r = build_network_review(_scan())
    assert r["available"]
    a = next(x for x in r["accounts"] if x["id"] == "111111111111")
    c = a["counts"]
    assert c["refused_in_internet"] == 50
    assert c["refused_in_private"] == 6  # from beta's range
    assert c["refused_out"] == 4 and c["refused_internal"] == 2
    assert c["unanswered"] == 5 and c["reset"] == 12
    assert a["where"] == {"internet": 55, "account": 18, "onprem": 4, "own": 2}
    flow = {(x["remote"], x["class"]): x for x in a["top"]}
    assert flow[("10.1.0.7", "refused_in_private")]["remote_account"] == "beta-prod"
    assert flow[("10.200.1.1", "refused_out")]["where"] == "onprem"
    assert a["new_pairs"] == 2 and a["new_inside"] == 2
    assert a["bytes"] == 3000 + 360 + 240 + 120 + 300 + 480


def test_review_names_recon_from_outside_and_a_sweep_from_inside():
    r = build_network_review(_scan())
    src = r["sources"][0]
    assert src["ip"] == "45.33.1.9" and src["port_count"] == 5 and src["recon"]
    look = {x["id"]: x for x in r["look"]}
    texts = [x["text"] for x in look["111111111111"]["reasons"]]
    assert any(t.startswith("10.1.0.9, inside the estate") for t in texts)
    assert any("timed out" in t for t in texts)
    assert r["look"][0]["id"] == "111111111111"
    # the internet knocking alone is not a reason to look
    assert not any("refused coming in from the internet" in t.lower() for t in texts)


def test_review_coverage_names_s3_only_and_missing_flow_logs_and_the_cost():
    cov = build_network_review(_scan())["coverage"]
    assert cov["flows_read"] == 1 and cov["tcp_read"] == 1 and cov["baseline_read"] == 1
    assert cov["s3_only"] == 1 and cov["s3_accounts"] == 1
    assert cov["no_flow_logs"] == 2 and cov["no_flow_log_accounts"] == 1
    assert cov["insights_cost"] == 0.02


def test_review_without_assurance_is_unavailable_and_ports_are_named():
    r = build_network_review({"id": "x", "accounts": []})
    assert not r["available"] and "Cloud Assurance" in r["reason"]
    assert port_name("22") == "22 (SSH)" and port_name("41000") == "41000"


def test_demo_review_has_new_failures_recon_and_every_class():
    r = build_network_review(build_demo_scan(6))
    assert r["new_count"] > 0 and r["totals"]["recon_accounts"] > 0
    assert {c["key"] for c in r["totals"]["classes"]} == {c["key"] for c in r["classes"]}


def test_network_endpoint():
    c = client()
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    r = c.post("/api/network", headers=H, json={"scan_id": scan_id, "filter": {"include": "prod"}})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] and all("prod" in a["name"] for a in body["accounts"])
    assert c.post("/api/network", headers=H, json={"scan_id": "nope"}).status_code == 404
    assert c.post("/api/network", json={"scan_id": scan_id}).status_code in (403, 400)
