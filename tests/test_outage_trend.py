from exitrisk.outage_trend import build_trend, comparable, direction, point


def _report(sid, at, score, rating="Medium", critical=1, high=2, accounts=10, blind=0, measures=1000):
    return {
        "available": True,
        "scan_id": sid,
        "scan_at": at,
        "label": "",
        "summary": {
            "score": score,
            "rating": rating,
            "critical": critical,
            "high": high,
            "medium": 0,
            "accounts": accounts,
            "accounts_blind": blind,
            "measures": measures,
            "critical_accounts": 0,
            "high_accounts": 1,
        },
    }


def _trend(current, earlier):
    by_id = {r["scan_id"]: point(r) for r in earlier}
    return build_trend(current, [{"id": r["scan_id"]} for r in earlier], by_id.get)


def test_comparable_same_ou_mode_earlier_only():
    cur = {"id": "c", "ou": "Root / Prod", "mode": "live", "created_at": "2026-11-06"}
    scans = [
        {
            "id": "a",
            "ou": "Root / Prod",
            "mode": "live",
            "status": "complete",
            "outage": True,
            "created_at": "2026-11-04",
        },
        {"id": "b", "ou": "Root", "mode": "live", "status": "complete", "outage": True, "created_at": "2026-11-04"},
        {
            "id": "d",
            "ou": "Root / Prod",
            "mode": "demo",
            "status": "complete",
            "outage": True,
            "created_at": "2026-11-04",
        },
        {
            "id": "e",
            "ou": "Root / Prod",
            "mode": "live",
            "status": "interrupted",
            "outage": True,
            "created_at": "2026-11-04",
        },
        {
            "id": "f",
            "ou": "Root / Prod",
            "mode": "live",
            "status": "complete",
            "outage": False,
            "created_at": "2026-11-04",
        },
        {
            "id": "g",
            "ou": "Root / Prod",
            "mode": "live",
            "status": "partial",
            "outage": True,
            "created_at": "2026-11-07",
        },
        {
            "id": "h",
            "ou": "Root / Prod",
            "mode": "live",
            "status": "partial",
            "outage": True,
            "created_at": "2026-11-01",
        },
        cur | {"status": "complete", "outage": True},
    ]
    assert [s["id"] for s in comparable(scans, cur)] == ["h", "a"]


def test_direction_needs_two_points():
    assert direction(2.0) == "worse"
    assert direction(-2.5) == "better"
    assert direction(1.9) == "steady"


def test_worse_since_previous_scan():
    t = _trend(_report("c", "2026-11-06", 48.9, critical=9), [_report("a", "2026-11-04", 42.4, critical=4)])
    assert t["direction"] == "worse"
    assert t["change"] == 6.5
    assert t["critical_change"] == 5
    assert [p["scan_id"] for p in t["points"]] == ["a", "c"]
    assert t["points"][-1]["current"] and t["points"][-1]["change"] == 6.5


def test_improving_and_steady():
    assert _trend(_report("c", "2", 30), [_report("a", "1", 40)])["direction"] == "better"
    assert _trend(_report("c", "2", 41), [_report("a", "1", 40)])["direction"] == "steady"


def test_single_scan_has_no_direction():
    t = _trend(_report("c", "2", 30), [])
    assert t["direction"] is None and len(t["points"]) == 1


def test_scan_reading_far_fewer_accounts_left_out():
    t = _trend(_report("c", "2", 50, accounts=100), [_report("a", "1", 20, accounts=40)])
    assert t["direction"] is None and t["left_out"] == 1


def test_carried_over_reads_kept_once():
    a = _report("a", "1", 42.5)
    copy = _report("b", "2", 42.5)  # a later scan that copied a's reads
    other = _report("x", "3", 42.4, critical=3)
    t = _trend(_report("c", "4", 48.0), [a, other, copy])
    assert [p["scan_id"] for p in t["points"]] == ["a", "x", "c"]


def test_older_scan_with_fewer_checks_marked_and_skipped_for_overall():
    old = _report("o", "1", 30, measures=600)
    a = _report("a", "2", 42)
    t = _trend(_report("c", "3", 45), [old, a])
    assert t["points"][0]["fewer_checks"] and not t["points"][0]["like_for_like"]
    assert t["first"]["scan_id"] == "a"
    assert t["overall_change"] == 3


def test_blind_scan_gives_no_point():
    assert point(_report("a", "1", 0, accounts=5, blind=5)) is None
    assert point({"available": False}) is None
