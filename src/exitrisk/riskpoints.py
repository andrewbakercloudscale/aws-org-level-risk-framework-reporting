"""Risk points, the same in every report, for the Risk by owner and Risk by account charts.

A hundred per critical, ten per high, one per medium, a tenth per low; a non-production account counts a tenth.
Each report says what its criticals, highs, mediums and lows are. Owner, executive, monthly spend and whether an
account is production come from the scan, so every report places an account in the same spot on the spend axis.
"""

from __future__ import annotations

POINTS = {"critical": 100, "high": 10, "medium": 1, "low": 0.1}
RATING = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
NONPROD = 0.1


def enrich(scan: dict, rows: list[dict], answers=None) -> None:
    """Add owner, executive, monthly_spend and production to each row (by its "id") where it has none."""
    from .assurance import _monthly_spend, prod_rule, production_why
    from .resilience import owner_of

    accounts = {a["id"]: a for a in scan.get("accounts") or []}
    spend = _monthly_spend(scan)
    prod = prod_rule(answers)
    for r in rows:
        acct = accounts.get(r.get("id")) or {"id": r.get("id"), "name": r.get("name", "")}
        if "owner" not in r or "executive" not in r:
            owner, executive = owner_of(acct)
            r.setdefault("owner", owner)
            r.setdefault("executive", executive)
        r.setdefault("monthly_spend", round(spend.get(r.get("id"), 0.0), 2))
        r.setdefault("production", production_why(acct, prod)[0])


def score(row: dict, severities: dict) -> None:
    """Set severities, risk and rating on a row from its count of criticals, highs, mediums and lows."""
    sev = {k: int(severities.get(k) or 0) for k in POINTS}
    row["severities"] = sev
    weight = 1 if row.get("production", True) else NONPROD
    row["risk"] = round(sum(POINTS[k] * n for k, n in sev.items()) * weight, 2)
    row["rating"] = next((RATING[k] for k in POINTS if sev[k]), "")
