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
