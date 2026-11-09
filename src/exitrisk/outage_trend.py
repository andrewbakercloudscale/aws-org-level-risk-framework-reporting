"""How the outage risk of one OU moves from scan to scan.

Every earlier scan of the same OU is scored again with the answers and account filter of the report being read,
and with today's date, so the line moves only when the estate does: a fix, a new limit, more load, a new risk.
A scan that read far fewer accounts is left out, as its score would describe a different estate.
"""

from __future__ import annotations

from collections.abc import Callable

# A change smaller than this is noise between two reads of the same estate: metrics move a little each day.
STEADY_POINTS = 2.0
# An earlier scan joins the line only when it rated at least this share of the accounts the current one rated.
MIN_COVERAGE = 0.5
# Below this share of the accounts rated, or of the measures read per account, the point is shown but marked:
# some of its move may be what was read (fewer accounts, or a scan made before newer checks), not the risk.
LIKE_FOR_LIKE = 0.9
MAX_POINTS = 12
STATUSES = ("complete", "partial")


def comparable(scans: list[dict], current: dict) -> list[dict]:
    """Earlier scans of the same OU and mode with the outage checks, oldest first. All are scan list entries."""
    ou = current.get("ou")
    at = current.get("created_at") or ""
    out = [
        s
        for s in scans
        if s.get("outage")
        and s["id"] != current.get("id")
        and s.get("ou") == ou
        and s.get("mode") == current.get("mode")
        and s.get("status") in STATUSES
        and (s.get("created_at") or "") < at
    ]
    return sorted(out, key=lambda s: s.get("created_at") or "")


def point(report: dict) -> dict | None:
    """The figures one scan gives the line, or None when it measured nothing."""
    if not report.get("available"):
        return None
    s = report["summary"]
    rated = s["accounts"] - s["accounts_blind"]
    if not rated:
        return None
    return {
        "scan_id": report.get("scan_id"),
        "scan_at": report.get("scan_at"),
        "label": report.get("label") or "",
        "score": s["score"],
        "rating": s["rating"],
        "critical": s["critical"],
        "high": s["high"],
        "medium": s["medium"],
        "rated": rated,
        "measures": s["measures"],
        "accounts": s["accounts"],
        "critical_accounts": s["critical_accounts"],
        "high_accounts": s["high_accounts"],
    }


def _same(a: dict, b: dict) -> bool:
    """Two scans that found exactly the same: a later scan that carried the earlier one's reads over."""
    keys = ("score", "critical", "high", "medium", "rated")
    return all(a[k] == b[k] for k in keys)


def direction(change: float) -> str:
    if change >= STEADY_POINTS:
        return "worse"
    if change <= -STEADY_POINTS:
        return "better"
    return "steady"


def build_trend(current: dict, earlier: list[dict], score_of: Callable[[str], dict | None]) -> dict:
    """The line for ``current`` (an outage report): its earlier scans, scored by ``score_of(scan_id)``."""
    now = point(current)
    if now is None:
        return {"points": [], "direction": None}
    points: list[dict] = []
    left_out = 0
    for s in earlier:
        p = score_of(s["id"])
        if p is None or p["rated"] < now["rated"] * MIN_COVERAGE:
            left_out += 1
            continue
        if any(_same(q, p) for q in points):
            continue  # a later scan that carried an earlier one's reads over: keep the first, when it was read
        points.append(p)
    if points and _same(points[-1], now):
        points.pop()  # the current scan carried the last one's reads over; it stands for both
    points = points[-(MAX_POINTS - 1) :]
    depth = now["measures"] / now["rated"]
    for p in points:
        p["fewer_accounts"] = p["rated"] < now["rated"] * LIKE_FOR_LIKE
        p["fewer_checks"] = p["measures"] / p["rated"] < depth * LIKE_FOR_LIKE
        p["like_for_like"] = not (p["fewer_accounts"] or p["fewer_checks"])
    line = [*points, {**now, "like_for_like": True, "fewer_accounts": False, "fewer_checks": False, "current": True}]
    for before, after in zip(line, line[1:], strict=False):
        after["change"] = round(after["score"] - before["score"], 1)
    if not points:
        return {"points": line, "direction": None, "left_out": left_out}
    prev = points[-1]
    # The overall move starts at the first like for like scan, when there is one: an older scan that read less
    # would show a rise that is only the newer checks.
    first = next((p for p in points if p["like_for_like"]), points[0])
    change = round(now["score"] - prev["score"], 1)
    overall = round(now["score"] - first["score"], 1)
    return {
        "points": line,
        "left_out": left_out,
        "direction": direction(change),
        "change": change,
        "previous": prev,
        "critical_change": now["critical"] - prev["critical"],
        "high_change": now["high"] - prev["high"],
        "overall_direction": direction(overall),
        "overall_change": overall,
        "first": first,
    }
