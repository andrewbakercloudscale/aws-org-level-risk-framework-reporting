"""A fault fixed after it last happened is left out of the actions; each line names every resource it covers."""

from datetime import date, datetime, timedelta, timezone

from exitrisk.collectors import outage_fixes as fixes
from exitrisk.collectors.outage import Series, search_fault
from exitrisk.outage import _since_fixed
from exitrisk.outage_views import _immediate, _others

T0 = datetime(2026, 10, 13, 13, 0, tzinfo=timezone.utc)


def _series(*hours_hit, n=48):
    s = Series()
    for h in range(n):
        s.add(T0 + timedelta(hours=h), 1.0 if h in hours_hit else 0.0)
    return s


def test_a_series_keeps_the_first_and_last_hour_it_was_above_zero():
    s = _series(3, 9, 20)
    assert s.first_hit == T0 + timedelta(hours=3) and s.last_hit == T0 + timedelta(hours=20)
    assert _series().last_hit is None
    assert fixes.hit_span(_series(5), _series(2), None) == (T0 + timedelta(hours=2), T0 + timedelta(hours=5))


def test_a_change_counts_as_a_fix_only_after_the_hour_the_fault_last_happened():
    last = T0 + timedelta(hours=20)
    got = fixes.fault_fields(T0, last, last + timedelta(days=3), "resized")
    assert got["changed"].startswith("2026-10-17") and got["change"] == "resized" and got["last"]
    assert "changed" not in fixes.fault_fields(T0, last, last + timedelta(minutes=30), "resized")  # same hour
    assert "changed" not in fixes.fault_fields(T0, last, T0, "resized")  # before it failed again
    assert fixes.fault_fields(None, None, last, "resized") == {}


def test_a_short_fault_beside_an_upgrade_happened_during_it_and_the_closest_change_is_named():
    changes = [(T0 - timedelta(minutes=40), "a cluster change"), (T0 + timedelta(hours=1), "an upgrade")]
    assert fixes.during(T0, T0, changes).startswith("an upgrade on")
    assert fixes.during(T0, T0 + timedelta(days=14), changes) is None  # weeks apart: not one change
    assert fixes.during(T0, T0, [(T0 + timedelta(days=2), "an upgrade")]) is None


class _Search:
    def __init__(self, cluster, engine):
        self.cluster, self.engine = cluster, engine

    def describe_domain_config(self, DomainName):
        st = lambda d: {"Status": {"UpdateDate": d}}  # noqa: E731
        return {"DomainConfig": {"ClusterConfig": st(self.cluster), "EBSOptions": st(T0 - timedelta(days=90)),
                                 "EngineVersion": st(self.engine)}}  # fmt: skip

    def describe_domain_change_progress(self, DomainName):
        return {"ChangeProgressStatus": {}}


def test_an_opensearch_fault_is_fixed_by_a_later_resize_or_put_down_to_the_upgrade_it_happened_during():
    red = _series(0)
    resized = search_fault(_Search(T0 + timedelta(days=20), T0 - timedelta(days=60)), "d", red)
    assert resized["change"] == "the domain's nodes or storage were changed"
    upgrade = search_fault(_Search(T0 - timedelta(days=60), T0 + timedelta(minutes=50)), "d", red)
    assert "changed" not in upgrade and upgrade["during"].startswith("an upgrade on")
    neither = search_fault(_Search(T0 - timedelta(days=60), T0 - timedelta(days=60)), "d", red)
    assert neither.keys() == {"first", "last"}


class _Table:
    def __init__(self, table):
        self.table = table

    def describe_table(self, TableName):
        return {"Table": self.table}


def test_a_table_is_fixed_by_going_on_demand_or_a_raise_by_hand_but_not_by_its_autoscaling():
    later = T0 + timedelta(days=5)
    on_demand = {"BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST", "LastUpdateToPayPerRequestDateTime": later}}
    assert fixes.table_raised(_Table(on_demand), "t", True) == (later, "the table moved to on demand")
    raised = {
        "BillingModeSummary": {"BillingMode": "PROVISIONED"},
        "ProvisionedThroughput": {"LastIncreaseDateTime": later},
    }
    assert fixes.table_raised(_Table(raised), "t", False) == (later, "the table's capacity was raised")
    assert fixes.table_raised(_Table(raised), "t", True) == (None, "")  # autoscaling raises it every day


def test_volume_changes_are_read_by_filter_so_a_volume_never_changed_is_no_error():
    class Ec2:
        def describe_volumes_modifications(self, Filters):
            assert Filters[0]["Name"] == "volume-id"
            return {"VolumesModifications": [
                {"VolumeId": "vol-1", "ModificationState": "completed", "StartTime": T0},
                {"VolumeId": "vol-1", "ModificationState": "failed", "StartTime": T0 + timedelta(days=9)},
            ]}  # fmt: skip

    assert fixes.volumes_modified(Ec2(), ["vol-1", "vol-2"]) == {"vol-1": T0}


def test_the_report_leaves_a_fixed_fault_out_puts_an_upgrade_blip_low_and_dates_the_rest():
    f = {"severity": "critical", "why": "1 seen red"}
    _since_fixed(f, {"last": "2026-10-13T13:30+02:00", "changed": "2026-11-06T14:40+02:00", "change": "resized"})
    assert f["recovered"] and f["fixed"] == "resized on 2026-11-06, after it last failed on 2026-10-13"
    f = {"severity": "critical", "why": "1 seen red"}
    _since_fixed(f, {"last": "2026-10-17T12:30+02:00", "during": "an upgrade on 2026-10-17T13:08+02:00"})
    assert f["severity"] == "low" and "an upgrade was being applied on 2026-10-17" in f["why"]
    f = {"severity": "critical", "why": "1 seen red"}
    _since_fixed(f, {"last": "2026-10-27T14:35+02:00"})
    assert f["severity"] == "critical" and f["why"].endswith("last on 2026-10-27") and f["last"]
    f = {"severity": "critical", "why": "x"}
    _since_fixed(f, {})
    assert f == {"severity": "critical", "why": "x"}  # older scans: as before


def test_each_line_names_every_resource_it_stands_for_and_the_fixed_ones_are_listed_apart():
    base = {"region": "af-south-1", "account_id": "1", "account": "prd-a", "title": "t", "days": None}
    base |= {"production": True, "service_label": "S", "why": "w", "rule": "search_red"}
    findings = [
        {**base, "res": "a", "severity": "critical", "pct": None, "last": "2026-10-27T14:35+02:00"},
        {**base, "res": "b", "severity": "critical", "pct": None},
        {**base, "res": "c", "severity": "critical", "pct": None},
    ]
    shown = findings[0]
    assert [o["res"] for o in _others(findings, shown)] == ["b", "c"]
    assert "account" in _others(findings, shown, account=True)[0]
    fixed = [{"rule": "search_red", "res": "z", "region": "r", "fixed": "resized on 2026-11-06", "title": "t"}]
    table = [{"id": "1", "name": "prd-a", "owner": "Team", "production": True, "fixed": fixed}]
    got = _immediate(findings, table, {"search_red": {"kind": "event", "fix": "f"}}, date(2026, 11, 9))
    row = got["rows"][0]
    assert row["when"] == "Last failed 2026-10-27" and row["more"] == 2 and len(row["others"]) == 2
    assert got["fixed"][0]["res"] == "z" and got["fixed"][0]["account"] == "prd-a"


class _Fake:
    """An AWS client answering the named calls with fixed pages; any other call answers empty."""

    def __init__(self, **answers):
        self.answers, self.calls = answers, []

    def can_paginate(self, _):
        return False

    def __getattr__(self, name):
        def call(**kw):
            self.calls.append((name, kw))
            got = self.answers.get(name, {})
            return got(**kw) if callable(got) else got

        return call


def _ctx(clients, metrics, region="r"):
    from collections import defaultdict

    from exitrisk.collectors import outage as collector

    class Session:
        def client(self, name, **_):
            return clients.setdefault(name, _Fake())

    ctx = collector.OutageCtx(Session(), "1", [region], {"services": None, "home": region})
    ctx.now = T0 + timedelta(days=30)
    ctx._metrics[region] = defaultdict(dict, metrics)
    return ctx


def _level(value, n=48):
    s = Series()
    for h in range(n):
        s.add(T0 + timedelta(hours=h), value)
    return s


def test_hours_at_a_threshold_are_read_across_pages_and_a_refused_read_leaves_the_fault_undated():
    from botocore.exceptions import ClientError

    t = [T0 + timedelta(hours=h) for h in range(4)]
    pages = iter([
        {"MetricDataResults": [{"Id": "h0", "Timestamps": t[:2], "Values": [29.8, 10.0]}], "NextToken": "n"},
        {"MetricDataResults": [{"Id": "h0", "Timestamps": t[2:], "Values": [30.0, 5.0]}]},
    ])  # fmt: skip
    cw = _Fake(get_metric_data=lambda **_: next(pages))
    wanted = {"f": ("AWS/Lambda", "Duration", {"FunctionName": "f"}, "Maximum", 29.7)}
    assert fixes.hours_at(cw, wanted, T0, T0 + timedelta(days=1), 3600) == {"f": (t[0], t[2])}

    def refuse(**_):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetMetricData")

    assert fixes.hours_at(_Fake(get_metric_data=refuse), wanted, T0, T0, 3600) == {}


def test_a_fault_quiet_for_a_week_is_one_level_lower_and_for_two_weeks_medium():
    last = T0 + timedelta(hours=5)
    assert fixes.fault_fields(T0, last, None, "", now=last + timedelta(days=10, hours=1))["quiet_days"] == 10.0
    for quiet, sev in ((2, "critical"), (10, "high"), (20, "medium")):
        f = {"severity": "critical", "why": "w"}
        _since_fixed(f, {"last": "2026-10-27T14:35+02:00", "quiet_days": quiet})
        assert f["severity"] == sev, quiet
    f = {"severity": "low", "why": "w"}
    _since_fixed(f, {"last": "2026-10-27T14:35+02:00", "quiet_days": 20})
    assert f["severity"] == "low"  # never raised


def test_an_on_demand_table_has_no_provisioned_ceiling_even_where_its_old_capacity_metric_says_one_unit():
    from exitrisk.collectors.outage import task_dynamodb

    metrics = {"ddb_rcu": {"t": _level(3600 * 9.4)}, "ddb_prcu": {"t": _level(1.0)}}
    on_demand = {"Table": {"BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"}}}
    ctx = _ctx({"dynamodb": _Fake(describe_table=on_demand)}, metrics)
    task_dynamodb(ctx, "r")
    assert not [r for r in ctx.rows if r["rule"] == "ddb_provisioned"]
    # provisioned: judged against today's setting, not the metric's last datapoint
    today = {"Table": {"ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 5}}}
    ctx = _ctx({"dynamodb": _Fake(describe_table=today)}, metrics)
    task_dynamodb(ctx, "r")
    row = next(r for r in ctx.rows if r["rule"] == "ddb_provisioned")
    assert row["limit"] == 10 and row["pct"] == 94.0


def test_connect_quota_breaches_and_rate_throttles_are_two_faults_with_their_own_dates():
    from exitrisk.collectors.outage import task_connect

    early, late = Series(), Series()
    for h in range(48):
        early.add(T0 + timedelta(hours=h), 5.0 if h < 3 else 0.0)
        late.add(T0 + timedelta(hours=h), 2.0 if h == 40 else 0.0)
    metrics = {"connect_breach": {"i1|VoiceCalls": early}, "connect_throttled": {"i1|VoiceCalls": late}}
    connect = _Fake(list_instances={"InstanceSummaryList": [{"Id": "i1", "InstanceAlias": "cc"}]})
    ctx = _ctx({"connect": connect}, metrics, "af-south-1")
    task_connect(ctx, "af-south-1")
    rows = {r["rule"]: r for r in ctx.rows if r["rule"] in ("connect_breach", "connect_throttled")}
    assert rows["connect_breach"]["used"] == 15 and rows["connect_breach"]["last"].startswith("2026-10-13T15")
    assert rows["connect_throttled"]["used"] == 2 and rows["connect_throttled"]["last"].startswith("2026-10-15T05")


def test_a_lambda_at_its_timeout_is_dated_by_the_last_run_that_reached_it():
    from exitrisk.collectors.outage_services import task_lambda_review

    hit = T0 + timedelta(hours=2)
    cw = _Fake(get_metric_data={"MetricDataResults": [{"Id": "h0", "Timestamps": [hit], "Values": [30000.0]}]})
    lam = _Fake(list_functions={"Functions": [{"FunctionName": "f", "Timeout": 30, "MemorySize": 128}]})
    ctx = _ctx({"lambda": lam, "cloudwatch": cw}, {"lambda_dur": {"f": _level(30000.0)}})
    task_lambda_review(ctx, "r")
    row = next(r for r in ctx.rows if r["rule"] == "lambda_timeout")
    assert row["last"].startswith("2026-10-13T15") and row["quiet_days"] >= 29


def test_reserved_concurrency_past_its_limit_is_fixed_by_the_change_when_no_throttle_came_after():
    from exitrisk.collectors.outage_services import _lambda_concurrency

    throttled = Series()
    for h in range(48):
        throttled.add(T0 + timedelta(hours=h), 9.0 if h < 5 else 0.0)
    metrics = {"lambda_fconc": {"f": _level(10.0)}, "lambda_throttle": {"f": throttled}}
    changed = T0 + timedelta(hours=20)
    trail = _Fake(lookup_events={"Events": [
        {"EventName": "UpdateFunctionCode20150331v2", "EventTime": T0 + timedelta(days=2)},
        {"EventName": "PutFunctionConcurrency20171031", "EventTime": changed},
    ]})  # fmt: skip
    lam = _Fake(get_function_concurrency={"ReservedConcurrentExecutions": 6})
    ctx = _ctx({"lambda": lam, "cloudtrail": trail}, metrics)
    _lambda_concurrency(ctx, lam, ctx.metrics("r"), [{"FunctionName": "f"}], "r")
    row = next(r for r in ctx.rows if r["rule"] == "lambda_reserved")
    assert row["pct"] == 166.7 and row["change"] == "the reserved concurrency was changed"
    assert row["changed"].startswith("2026-10-14T09") and "trigger" not in row


def test_a_queue_fed_function_at_its_reserved_concurrency_is_backpressure_not_an_outage():
    from exitrisk.collectors.outage_services import _lambda_concurrency

    maps = {"EventSourceMappings": [{"State": "Enabled", "EventSourceArn": "arn:aws:sqs:r:1:bulk"}]}
    lam = _Fake(get_function_concurrency={"ReservedConcurrentExecutions": 50}, list_event_source_mappings=maps)
    ctx = _ctx({"lambda": lam}, {"lambda_fconc": {"f": _level(50.0)}})
    _lambda_concurrency(ctx, lam, ctx.metrics("r"), [{"FunctionName": "f"}], "r")
    row = next(r for r in ctx.rows if r["rule"] == "lambda_reserved")
    assert row["trigger"] == "poller"
    found = _report([row])
    assert found[0]["severity"] == "low" and "poller" in found[0]["why"]


def _report(rows, profiles=()):
    from exitrisk.outage import build_outage

    scan = {"accounts": [{"id": "1", "name": "prod", "ou_path": "Root"}], "params": {"outage": True}}
    scan["outage"] = {"accounts": {"1": {"rows": rows, "clusters": [], "checks": {}, "regions": ["r"],
                                         "profiles": list(profiles)}}}  # fmt: skip
    return build_outage(scan)["findings"]


def test_a_saved_scan_drops_provisioned_capacity_on_a_table_its_review_says_is_on_demand():
    row = {"rule": "ddb_provisioned", "res": "log read", "region": "r", "pct": 940.6, "used": 9.4, "limit": 1,
           "load": True, "note": "no autoscaling"}  # fmt: skip
    review = {"svc": "dynamodb", "res": "log", "region": "r", "facts": {"Mode": "on demand"}, "stats": []}
    assert _report([row], [review]) == []
    assert _report([row], [{**review, "facts": {"Mode": "provisioned"}}])


def test_a_dead_letter_queue_alarmed_on_messages_visible_has_its_alarm():
    from exitrisk.collectors.outage_services import finish_alarms

    ctx = _ctx({}, {})
    ctx.alarm_wants = [("sqs", "orders-dlq", "r", "orders-dlq"), ("sqs", "jobs", "r", "jobs")]
    ctx.alarms["r"] = {("AWS/SQS", "ApproximateNumberOfMessagesVisible", "orders-dlq")}
    finish_alarms(ctx)
    assert [r["res"] for r in ctx.rows if r["rule"] == "no_alarm"] == ["sqs: jobs"]
