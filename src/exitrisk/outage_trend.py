"""How the outage risk of one OU moves from scan to scan.

Every earlier scan of the same OU is scored again with the answers and account filter of the report being read,
and with today's date, so the line moves only when the estate does: a fix, a new limit, more load, a new risk.
A scan that read far fewer accounts is left out, as its score would describe a different estate.
"""

from __future__ import annotations

from collections.abc import Callable

from .outage_views import owner_health

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
        "owners": owner_health(report.get("accounts") or []),
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


def _lean(points: list[dict]) -> list[dict]:
    """The points as sent to the page: without each owner's figures, which only the ranking below needs."""
    return [{k: v for k, v in p.items() if k != "owners"} for p in points]


HEALTHY_POINTS = 5  # an account made healthy is worth this many improvement points, beside each risk point removed


def _gains(now: dict, before: dict) -> list[dict]:
    """Every owner who improved from ``before`` to ``now``, judged only on the accounts the owner had in both scans
    and that both scans read in full: a check not read in one scan would look like a fix, or a new account like a
    change. The owner's accounts must also be about the same set (LIKE_FOR_LIKE), so a move is not a new estate."""
    out = []
    for owner, n in (now.get("owners") or {}).items():
        b = (before.get("owners") or {}).get(owner)
        if not b or "each" not in n or "each" not in b:
            continue
        if min(n["accounts"], b["accounts"]) < max(n["accounts"], b["accounts"]) * LIKE_FOR_LIKE:
            continue
        both = sorted(set(n["each"]) & set(b["each"]))
        if len(both) < max(n["accounts"], b["accounts"]) * LIKE_FOR_LIKE:
            continue  # too few accounts read in full in both scans to say the owner improved
        was = sum(b["each"][a][0] for a in both) / len(both)
        is_ = sum(n["each"][a][0] for a in both) / len(both)
        fell = round(was - is_, 1)
        gained = sum(n["each"][a][1] for a in both) - sum(b["each"][a][1] for a in both)
        if fell >= STEADY_POINTS or gained > 0:
            points = round(max(fell, 0) + HEALTHY_POINTS * max(gained, 0), 1)
            out.append({"owner": owner, "accounts": len(both), "score_before": round(was, 1), "score": round(is_, 1),
                        "fell": fell, "healthy_before": sum(b["each"][a][1] for a in both),
                        "healthy": sum(n["each"][a][1] for a in both), "gained": gained, "points": points})  # fmt: skip
    return out


def race(line: list[dict]) -> dict:
    """The improvement race: each scan's improvements by owner (the timeline) and the season's leaderboard.
    Points: one per risk point an owner's average fell by, and HEALTHY_POINTS per account made healthy. Only
    improvements score; an owner who slips back earns nothing that scan and is not docked."""
    events, board = [], {}
    for before, after in zip(line, line[1:], strict=False):
        if "owners" not in before or "owners" not in after:
            continue
        ups = sorted(_gains(after, before), key=lambda r: (-r["points"], r["owner"].lower()))
        for u in ups:
            o = board.setdefault(u["owner"], {"owner": u["owner"], "points": 0.0, "fell": 0.0, "gained": 0, "wins": 0,
                                              "timeline": []})  # fmt: skip
            o["points"] = round(o["points"] + u["points"], 1)
            o["fell"] = round(o["fell"] + max(u["fell"], 0), 1)
            o["gained"] += max(u["gained"], 0)
            o["timeline"].append({"scan_at": after.get("scan_at"), "points": u["points"]})
        if ups:
            board[ups[0]["owner"]]["wins"] += 1
        events.append({"scan_at": after.get("scan_at"), "since": before.get("scan_at"), "owners": ups[:8],
                       "more": max(len(ups) - 8, 0)})  # fmt: skip
    leaders = sorted(board.values(), key=lambda r: (-r["points"], -r["gained"], r["owner"].lower()))
    first = next((p for p in line if "owners" in p), None)
    return {
        "events": events,
        "leaders": leaders[:15],
        "owners": len(board),
        "since": first.get("scan_at") if first else None,
        "scans": [p.get("scan_at") for p in line if "owners" in p],
        "healthy_points": HEALTHY_POINTS,
    }


def most_improved(now: dict, before: dict) -> list[dict]:
    """Owners whose accounts got healthier since ``before``: the risk score fell by at least STEADY_POINTS, or more
    accounts are healthy. Only owners with about the same accounts in both scans, so a move is not a new estate."""
    out = _gains(now, before)
    out.sort(key=lambda r: (-r["fell"], -r["gained"], r["owner"].lower()))
    return out[:10]


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
        return {"points": _lean(line), "direction": None, "left_out": left_out, "race": race(line)}
    prev = points[-1]
    # The overall move starts at the first like for like scan, when there is one: an older scan that read less
    # would show a rise that is only the newer checks.
    first = next((p for p in points if p["like_for_like"]), points[0])
    change = round(now["score"] - prev["score"], 1)
    overall = round(now["score"] - first["score"], 1)
    return {
        "points": _lean(line),
        "left_out": left_out,
        "direction": direction(change),
        "change": change,
        "previous": _lean([prev])[0],
        "critical_change": now["critical"] - prev["critical"],
        "high_change": now["high"] - prev["high"],
        "overall_direction": direction(overall),
        "overall_change": overall,
        "first": _lean([first])[0],
        "improved": most_improved(now, prev),
        "race": race(line),
    }
