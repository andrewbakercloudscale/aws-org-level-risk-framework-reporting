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


def _acct(owner, rating, score, high=0, id="", unread=()):
    return {"id": id, "owner": owner, "rating": rating, "score": score, "critical": 0, "high": high,
            "production": True, "not_measured": list(unread)}  # fmt: skip


def test_cloud_athletes_rank_by_share_healthy_with_small_owners_last():
    from exitrisk.outage_views import _athletes

    big = [_acct("big", "Low", 20, id=f"b{i}") for i in range(8)] + [
        _acct("big", "High", 60, high=1, id=f"bh{i}") for i in range(6)]  # fmt: skip
    neat = [_acct("neat", "Low", 5, id=f"n{i}") for i in range(4)] + [_acct("neat", "Medium", 20, id="n4")]
    tiny = [_acct("tiny", "Low", 3, id="t0"), _acct("tiny", "Low", 3, id="t1")]
    best = _athletes(big + neat + tiny)
    assert [o["owner"] for o in best] == ["neat", "big", "tiny"]  # 80% beats 57%; 2 of 2 is too few to rank
    assert [o["small"] for o in best] == [False, False, True]


def test_cloud_athletes_leave_out_untagged_and_most_improved_needs_the_same_estate():
    from exitrisk.outage_trend import most_improved
    from exitrisk.outage_views import _athletes, owner_health

    table = [_acct("cards", "Low", 5, id="c1"), _acct("cards", "Low", 8, id="c2"), _acct("pay", "Low", 2, id="p1"),
             _acct("pay", "High", 60, high=2, id="p2"), _acct("", "Low", 1, id="x"),
             _acct("ops", "Not measured", 0, id="o"), _acct("data", "Medium", 30, high=1, id="d1"),
             _acct("data", "Medium", 30, high=1, id="d2")]  # fmt: skip
    best = _athletes(table)
    assert {o["owner"] for o in best} == {"cards", "pay"}  # no tag, not measured and no healthy account: left out
    assert best[0]["owner"] == "cards" and best[0]["healthy"] == 2 and best[1]["share"] == 0.5
    assert "each" not in best[0]
    before = owner_health([_acct("pay", "High", 60, high=2, id="p1"), _acct("pay", "High", 60, high=2, id="p2"),
                           _acct("cards", "Low", 5, id="c1"), _acct("data", "High", 70, high=3, id="d1", unread=["x"]),
                           _acct("data", "High", 70, high=3, id="d2")])  # fmt: skip
    up = most_improved({"owners": owner_health(table)}, {"owners": before})
    # cards went from 1 account to 2: a different estate. data's d1 was not read in full before, so only d2 compares:
    # too few of its accounts to say it improved, as an unread check must not look like a fix.
    assert [o["owner"] for o in up] == ["pay"]
    assert up[0]["fell"] == 29.0 and up[0]["gained"] == 1


def test_the_improvement_race_scores_each_step_and_never_docks_a_slip():
    from exitrisk.outage_trend import HEALTHY_POINTS, race

    def pt(at, **owners):
        mine = {}
        for k, (score, healthy) in owners.items():
            each = {f"{k}{i}": [score, i < healthy] for i in range(4)}
            mine[k] = {"accounts": 4, "healthy": healthy, "score": score, "production": 4, "each": each}
        return {"scan_at": at, "owners": mine}

    line = [pt("2026-10-01", cards=(50, 0), pay=(40, 1)), pt("2026-10-15", cards=(30, 1), pay=(45, 1)),
            pt("2026-11-01", cards=(31, 1), pay=(20, 2)), {"scan_at": "2026-11-02"}]  # fmt: skip
    r = race(line)
    assert [e["scan_at"] for e in r["events"]] == ["2026-10-15", "2026-11-01"]  # a point without owners is skipped
    board = {o["owner"]: o for o in r["leaders"]}
    assert board["cards"]["points"] == 20 + HEALTHY_POINTS and board["cards"]["wins"] == 1  # the slip costs nothing
    assert board["pay"]["points"] == 25 + HEALTHY_POINTS and board["pay"]["wins"] == 1
    assert r["leaders"][0]["owner"] == "pay"


def test_risk_spectators_never_name_an_owner_who_fixed_anything():
    from exitrisk.outage_trend import race

    def own(score, healthy, n=4, start=0):
        each = {f"a{start + i}": [score, i < healthy] for i in range(n)}
        return {"accounts": n, "healthy": healthy, "score": score, "production": n, "each": each}

    grew = own(70, 0)
    grew_after = {**own(70, 0, n=8), "each": {**own(70, 0, n=8)["each"], "a0": [60, False]}}  # one fix, estate doubled
    first = {"idle": own(80, 0), "busy": own(90, 0), "fine": own(5, 4), "tiny": own(30, 1), "grew": grew}
    then = {"idle": own(80.5, 0), "busy": own(60, 0), "fine": own(5, 4), "tiny": own(29.5, 1), "grew": grew_after,
            "new": own(99, 0)}  # fmt: skip
    line = [{"scan_at": "2026-10-01", "owners": first}, {"scan_at": "2026-10-15", "owners": then}]
    r = race(line)
    assert "grew" not in {o["owner"] for o in r["leaders"]}  # the race skips a changed estate...
    # ...but the fix still counts here. busy fixed; fine is healthy; new has one scan; a 0.5 drift is not a fix.
    assert [o["owner"] for o in r["spectators"]] == ["idle", "tiny"]


def test_fixing_too_slowly_names_big_risks_with_a_small_share_fixed():
    from exitrisk.outage_trend import race

    def own(scores, healthy=()):
        each = {f"a{i}": [sc, i in healthy] for i, sc in enumerate(scores)}
        return {"accounts": len(scores), "healthy": len(healthy), "score": sum(scores) / len(scores),
                "production": len(scores), "each": each}  # fmt: skip

    big0, big1 = own([80] * 10), own([80] * 9 + [70])  # 10 removed of 790 left: 1.3%
    keen0, keen1 = own([60, 60]), own([20, 60])  # 40 removed of 80 left: a third
    idle = own([90, 90])
    line = [
        {"scan_at": "2026-10-01", "owners": {"big": big0, "keen": keen0, "idle": idle}},
        {"scan_at": "2026-10-15", "owners": {"big": big1, "keen": keen1, "idle": idle}},
    ]
    r = race(line)
    assert [o["owner"] for o in r["slow"]] == ["big"]
    assert r["slow"][0]["removed"] == 10 and r["slow"][0]["share"] < 0.02
    assert [o["owner"] for o in r["spectators"]] == ["idle"]  # fixed nothing: a spectator, not slow


def test_a_fix_that_comes_back_is_not_risk_removed():
    from exitrisk.outage_trend import race

    def own(score, healthy):
        return {
            "accounts": 1,
            "healthy": int(healthy),
            "score": score,
            "production": 1,
            "each": {"a": [score, healthy]},
        }

    swing = [own(80, False), own(5, True), own(80, False), own(5, True), own(80, False)]
    line = [{"scan_at": f"2026-10-0{i + 1}", "owners": {"swing": o}} for i, o in enumerate(swing)]
    slow = race(line)["slow"]
    assert slow[0]["owner"] == "swing" and slow[0]["fixes"] == 2 and slow[0]["removed"] == 0


def test_fixing_too_slowly_judges_on_critical_accounts():
    from exitrisk.outage_trend import race

    def own(scores):
        each = {f"a{i}": [sc, sc < 25] for i, sc in enumerate(scores)}
        return {"accounts": len(scores), "healthy": sum(sc < 25 for sc in scores),
                "score": sum(scores) / len(scores), "production": len(scores), "each": each}  # fmt: skip

    # Medium accounts fixed (60 -> 10 twice: 100 removed of 440 left overall, 18%), criticals untouched: slow.
    line = [
        {"scan_at": "2026-10-01", "owners": {"judi": own([90, 90, 90, 60, 60])}},
        {"scan_at": "2026-10-15", "owners": {"judi": own([89, 90, 90, 10, 10])}},
    ]
    slow = race(line)["slow"]
    assert slow[0]["owner"] == "judi" and slow[0]["on_critical"] and slow[0]["share"] < 0.01
