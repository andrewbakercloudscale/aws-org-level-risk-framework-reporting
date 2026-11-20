"""Risk points are the same in every report, so each can draw Risk by owner and Risk by account."""

from __future__ import annotations

from exitrisk import riskpoints
from exitrisk.access_graph import build_access
from exitrisk.compromise import build_compromise
from exitrisk.demo import build_demo_scan
from exitrisk.multiregion import build_multiregion
from exitrisk.ssm_review import build_ssm_review

FIELDS = {"id", "name", "owner", "executive", "monthly_spend", "production"}


def test_points_and_rating():
    row = {"production": True}
    riskpoints.score(row, {"critical": 1, "high": 2, "medium": 3, "low": 4})
    assert row["risk"] == 100 + 20 + 3 + 0.4 and row["rating"] == "Critical"
    quiet = {"production": False}
    riskpoints.score(quiet, {"high": 1})
    assert quiet["risk"] == 1 and quiet["rating"] == "High"
    none = {}
    riskpoints.score(none, {})
    assert none["risk"] == 0 and none["rating"] == ""


def test_enrich_keeps_what_a_row_already_has():
    scan = build_demo_scan(6)
    first = scan["accounts"][0]
    rows = [{"id": first["id"], "owner": "Kept", "executive": "Also kept"}]
    riskpoints.enrich(scan, rows)
    assert rows[0]["owner"] == "Kept" and rows[0]["executive"] == "Also kept"
    assert rows[0]["monthly_spend"] >= 0 and isinstance(rows[0]["production"], bool)


def test_every_report_scores_its_accounts():
    scan = build_demo_scan(6)
    for rows in (
        build_ssm_review(scan)["accounts"],
        build_compromise(scan)["accounts"],
        build_multiregion(scan)["accounts"],
    ):
        assert rows
        for a in rows:
            assert FIELDS <= a.keys() and {"risk", "rating", "severities"} <= a.keys()
        assert any(a["risk"] > 0 for a in rows)
    access = build_access(scan)["accounts"]
    assert access and all(FIELDS <= a.keys() and {"in", "in_by"} <= a.keys() for a in access)
