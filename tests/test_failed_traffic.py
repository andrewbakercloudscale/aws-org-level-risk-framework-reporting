"""Failed and blocked traffic: CloudWatch failure metrics per region, refused API calls from CloudTrail, and
the account map's section that lists every kind, 0 included, with the sources and callers refused."""

from datetime import datetime, timezone

from test_access_graph import OWN, PEER, _net, _scan
from test_account_map import _assets
from test_assurance import FakeClient, _ctx

import exitrisk.collectors.assurance as checks
from exitrisk.account_map import FAIL_CATS, build_account_map
from exitrisk.collectors import access
from exitrisk.demo import build_demo_scan

T = datetime(2026, 11, 17, 10, tzinfo=timezone.utc)


def _cw(series: dict):
    """A CloudWatch client answering GetMetricData: series is {metric name: {label: [values]}}."""
    asked = []

    def get_metric_data(MetricDataQueries, **_kw):  # noqa: N803
        asked.append(MetricDataQueries)
        out = []
        for q in MetricDataQueries:
            metric = q["Expression"].split('MetricName="')[1].split('"')[0]
            for label, values in (series.get(metric) or {}).items():
                out.append({"Id": q["Id"], "Label": label, "Timestamps": [T] * len(values), "Values": values})
        return {"MetricDataResults": out}

    c = FakeClient({"get_metric_data": get_metric_data})
    c.asked = asked
    return c


def test_queries_cover_every_metric_and_cloudfront_waf_only_in_us_east_1():
    q = access.failure_queries("eu-west-1")
    exprs = " ".join(x["Expression"] for x in q)
    for metric in ("HTTPCode_ELB_4XX_Count", "SecurityGroupBlockedFlowCount_Inbound_TCP", "BlockedRequests",
                   "DroppedPackets", "ErrorPortAllocation", "PacketDropCountBlackhole", "4XXError", "PacketsDropped",
                   "LoginFailures"):  # fmt: skip
        assert f'MetricName="{metric}"' in exprs
    assert "{AWS/WAFV2,Region,Rule,WebACL}" in exprs and "{AWS/WAFV2,Rule,WebACL}" not in exprs
    assert '"VPC Endpoint Id"' in exprs  # dimension names with spaces are quoted
    us = " ".join(x["Expression"] for x in access.failure_queries("us-east-1"))
    assert "{AWS/WAFV2,Rule,WebACL}" in us
    assert all(len({x["Id"] for x in q}) == len(q) for q in (q,))


def test_totals_keep_every_key_and_scale_rates_to_counts():
    q = access.failure_queries("eu-west-1")
    by_key = {x.get("_key") or x["_present"]: x["Id"] for x in q}
    data = {
        by_key["alb_elb_4xx"]: {"app/web/1": [(T, 5.0), (T, 7.0)], "app/api/2": [(T, 1.0)]},
        by_key["db_login"]: {"aurora-1": [(T, 0.01)]},  # failures per second, averaged over the hour
        by_key["alb"]: {"app/web/1": [(T, 60.0)], "app/api/2": [(T, 60.0)], "app/idle/3": [(T, 60.0)]},
    }
    metrics, present = access.failure_totals(q, data)
    assert set(access.FAIL_METRICS) <= set(metrics)  # every key, 0 when nothing was published
    assert metrics["alb_elb_4xx"] == {"total": 13, "top": [["app/web/1", 12], ["app/api/2", 1]], "resources": 2}
    assert metrics["db_login"]["total"] == 36  # 0.01 a second for an hour
    assert metrics["nat_drop"] == {"total": 0, "top": [], "resources": 0}
    assert present["alb"] == 3 and present["nat"] == 0


def test_task_reads_metrics_and_names_a_refusal():
    cw = _cw({"HTTPCode_ELB_4XX_Count": {"app/web/1": [4.0, 6.0]}, "ConsumedLCUs": {"app/web/1": [1.0]}})
    ctx = _ctx({"cloudwatch": cw})
    task = next(t for t in checks.REGION_TASKS if t[0] == "access-failures")
    checks._run(ctx, task, "eu-west-1")
    f = ctx.r.facts["access_failures"]["eu-west-1"]
    assert f["metrics"]["alb_elb_4xx"]["total"] == 10 and f["present"]["alb"] == 1
    assert len(cw.asked) == 1  # one round for the region
    refused = _ctx({})  # every call refused
    checks._run(refused, task, "eu-west-1")
    f = refused.r.facts["access_failures"]["eu-west-1"]
    assert "metrics" not in f and "CloudWatch metrics" in f["refused"][0]


def test_trail_denials_read_only_with_flows_and_only_from_own_log_groups():
    queries = []
    rows = [[{"field": "account", "value": OWN}, {"field": "who", "value": "arn:aws:iam::1:user/x"},
             {"field": "ip", "value": "185.220.101.34"}, {"field": "svc", "value": "iam.amazonaws.com"},
             {"field": "call", "value": "ListUsers"}, {"field": "code", "value": "AccessDenied"},
             {"field": "n", "value": "7"}]]  # fmt: skip
    logs = FakeClient({
        "start_query": lambda **kw: queries.append(kw) or {"queryId": f"q{len(queries)}"},
        "get_query_results": lambda queryId: {"status": "Complete", "results": rows if queryId == "q1" else [  # noqa: N803
            [{"field": "account", "value": OWN}, {"field": "n", "value": "9"}]]},
    })  # fmt: skip
    ct = FakeClient({"describe_trails": {"trailList": [
        {"Name": "org", "IsOrganizationTrail": True,
         "CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-west-1:111111111111:log-group:org-trail:*"},
        {"Name": "theirs",
         "CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-west-1:999999999999:log-group:x:*"}]}})  # fmt: skip
    task = next(t for t in checks.GLOBAL_TASKS if t[0] == "trail-denials")
    off = _ctx({"cloudtrail": ct, "logs": logs})
    checks._run(off, task, None)
    assert "trail_denials" not in off.r.facts and not queries  # Insights costs money: only when asked
    on = _ctx({"cloudtrail": ct, "logs": logs}, info={"flows": True})
    checks._run(on, task, None)
    t = on.r.facts["trail_denials"]
    assert t["read"] and t["org"] and [q["logGroupNames"] for q in queries] == [["org-trail"], ["org-trail"]]
    assert t["rows"][0] == {"account": OWN, "who": "arn:aws:iam::1:user/x", "ip": "185.220.101.34",
                            "svc": "iam.amazonaws.com", "call": "ListUsers", "code": "AccessDenied",
                            "n": 7}  # fmt: skip
    assert t["totals"] == {OWN: 9}
    assert "AccessDenied" in queries[0]["queryString"] and "ConsoleLogin" in queries[0]["queryString"]


# ---------------------------------------------------------------------------------- the account map


def _metrics(**totals):
    m = {k: {"total": 0, "top": [], "resources": 0} for k in access.FAIL_METRICS}
    for k, (name, v) in totals.items():
        m[k] = {"total": v, "top": [[name, v]], "resources": 1}
    return m


def test_every_kind_listed_with_zero_and_flags_on_the_node():
    assets = _assets("10.1.0.0/16", lbs=[{"name": "web", "type": "application", "vpc": "vpc-1", "dns": "web.elb"}])
    fails = {"eu-west-1": {"hours": 24, "metrics": _metrics(alb_elb_4xx=("app/web/abc", 120),
                                                             nlb_sg_in_tcp=("net/edge/1", 5),
                                                             nlb_sg_in_udp=("net/edge/1", 2)),
                           "present": {"alb": 1, "nlb": 1}}}  # fmt: skip
    m = build_account_map(_scan({OWN: {"access_network": _net("10.1.0.0/16"), "access_assets": assets,
                                       "access_failures": fails}}), OWN)  # fmt: skip
    f = m["failures"]
    rows = {r["key"]: r for r in f["rows"]}
    assert [r["key"] for r in f["rows"]] == [c[0] for c in FAIL_CATS]  # every kind, in order
    assert rows["alb_elb_4xx"]["total"] == 120 and rows["alb_elb_4xx"]["top"][0]["node"] == "lb:eu-west-1:web"
    assert rows["nlb_sg_in"]["total"] == 7  # TCP, UDP and ICMP together
    assert (rows["alb_elb_5xx"]["state"], rows["alb_elb_5xx"]["total"]) == ("read", 0)  # a 0 is shown
    assert rows["tgw_blackhole"]["state"] == "none_here"
    assert rows["flow_in"]["state"] == "not_read" and "flow logs not read" in rows["flow_in"]["note"]
    assert rows["trail_denied"]["state"] == "not_read"
    web = next(n for n in m["nodes"] if n["id"] == "lb:eu-west-1:web")
    assert any("120 requests refused" in x for x in web["flags"])


def test_old_scans_say_a_new_scan_is_needed():
    own = {"access_network": _net("10.1.0.0/16"), "access_assets": _assets("10.1.0.0/16")}
    m = build_account_map(_scan({OWN: own}), OWN)
    waf = next(r for r in m["failures"]["rows"] if r["key"] == "waf_blocked")
    assert (waf["state"], waf["note"]) == ("not_read", "needs a new scan")


def test_refused_sources_show_sweeps_databases_and_other_accounts():
    assets = _assets("10.1.0.0/16", igws=[{"id": "igw-1", "vpc": "vpc-1"}])
    sweep = [{"src": "185.220.101.34", "dst": "10.1.1.9", "port": p, "bytes": 60, "flows": 3}
             for p in ("21", "22", "23", "3306", "5432")]  # fmt: skip
    rejected = [*sweep, {"src": "10.1.1.9", "dst": "91.198.174.192", "port": "443", "bytes": 40, "flows": 2}]
    flows = {"eu-west-1": {"hours": 24, "rows": [], "total_bytes": 0, "covered": ["vpc-1"], "s3_only": [],
                           "rejected": rejected, "reject_covered": ["vpc-1"]}}  # fmt: skip
    peer_flows = {"eu-west-1": {"hours": 24, "rows": [], "covered": [], "s3_only": [], "reject_covered": ["vpc-2"],
                                "rejected": [{"src": "185.220.101.34", "dst": "10.2.0.4", "port": "22", "bytes": 1,
                                              "flows": 1}]}}  # fmt: skip
    m = build_account_map(_scan({
        OWN: {"access_network": _net("10.1.0.0/16"), "access_assets": assets, "access_flows": flows},
        PEER: {"access_network": _net("10.2.0.0/16"), "access_assets": _assets("10.2.0.0/16"),
               "access_flows": peer_flows},
    }), OWN)  # fmt: skip
    f = m["failures"]
    rows = {r["key"]: r for r in f["rows"]}
    assert (rows["flow_in"]["total"], rows["flow_internet"]["total"], rows["flow_out"]["total"]) == (15, 15, 2)
    assert rows["flow_db"]["total"] == 6 and "MySQL" in " ".join(t["name"] for t in rows["flow_db"]["top"])
    top = f["sources"]["rows"][0]
    assert top["remote"] == "185.220.101.34" and top["port_count"] == 5 and top["attempts"] == 15
    assert [a["id"] for a in top["elsewhere"]] == [PEER]
    org = f["org"]["sources"][0]
    assert org["ip"] == "185.220.101.34" and org["account_count"] == 2 and org["both"] is False


def test_callers_grouped_from_an_organisation_trail_in_another_account():
    calls = [{"account": OWN, "who": "arn:aws:sts::1:assumed-role/ci/s", "ip": "185.220.101.34",
              "svc": f"{s}.amazonaws.com", "call": c, "code": "AccessDenied", "n": 2}
             for s, c in (("iam", "ListUsers"), ("s3", "ListBuckets"), ("kms", "ListKeys"))]  # fmt: skip
    calls += [{"account": OWN, "who": "root", "ip": "196.25.7.80", "svc": "signin.amazonaws.com",
               "call": "ConsoleLogin", "code": "", "n": 4},
              {"account": PEER, "who": "x", "ip": "185.220.101.34", "svc": "iam.amazonaws.com", "call": "ListUsers",
               "code": "AccessDenied", "n": 1}]  # fmt: skip
    trail = {"hours": 24, "read": True, "org": True, "rows": calls, "totals": {OWN: 10, PEER: 1}}
    m = build_account_map(_scan({
        OWN: {"access_network": _net("10.1.0.0/16"), "access_assets": _assets("10.1.0.0/16")},
        PEER: {"access_network": _net("10.2.0.0/16"), "access_assets": _assets("10.2.0.0/16"),
               "trail_denials": trail},
    }), OWN)  # fmt: skip
    f = m["failures"]
    rows = {r["key"]: r for r in f["rows"]}
    assert (rows["trail_denied"]["total"], rows["trail_login"]["total"]) == (6, 4)
    ci = next(c for c in f["callers"]["rows"] if c["ip"] == "185.220.101.34")
    assert ci["call_count"] == 3 and ci["n"] == 6 and [a["id"] for a in ci["elsewhere"]] == [PEER]
    login = next(c for c in f["callers"]["rows"] if c["who"] == "root")
    assert login["codes"] == ["Failed sign-in"]
    assert f["org"]["callers"][0]["ip"] == "185.220.101.34" and f["org"]["callers"][0]["account_count"] == 2
    demo = build_demo_scan()
    org = build_account_map(demo, next(a["id"] for a in demo["accounts"] if "digital-channels-prod" in a["name"]))
    assert next(x for x in org["failures"]["org"]["callers"] if x["ip"] == "185.220.101.34")["both"] is True


def test_trail_in_an_unrelated_account_does_not_cover_this_one():
    trail = {"hours": 24, "read": True, "org": False, "rows": [], "totals": {}}
    m = build_account_map(_scan({
        OWN: {"access_network": _net("10.1.0.0/16"), "access_assets": _assets("10.1.0.0/16")},
        PEER: {"access_network": _net("10.2.0.0/16"), "access_assets": _assets("10.2.0.0/16"),
               "trail_denials": trail},
    }), OWN)  # fmt: skip
    row = next(r for r in m["failures"]["rows"] if r["key"] == "trail_denied")
    assert row["state"] == "not_read" and "organisation trail" in row["note"]


def test_demo_shows_a_scan_and_enumeration():
    scan = build_demo_scan()
    names = {a["id"]: a["name"] for a in scan["accounts"]}
    digital = next(i for i, n in names.items() if "digital-channels-prod" in n)
    f = build_account_map(scan, digital)["failures"]
    assert f["sources"]["rows"][0]["port_count"] >= 5 and f["sources"]["rows"][0]["elsewhere"]
    assert any(c["call_count"] >= 10 for c in f["callers"]["rows"])
    assert next(r for r in f["rows"] if r["key"] == "waf_blocked")["total"] > 0
