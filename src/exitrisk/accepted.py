"""Accepted risks: findings a team has looked at and chosen to live with, for a stated reason, until a review date.

A rule names resources by a name pattern (``prophet*``) or a tag (``risk-accepted=true``), optionally narrowed to
some checks and accounts, so a whole fleet is covered at once, servers added later included. A finding a rule
covers leaves the counts, the scores and Immediate attention, and is listed under Accepted risks with who
accepted it and why. It comes back on the review date, or as soon as its reading is worse than when it was accepted.

Rules are kept in one file in the data directory, beside the scans, so every report and export reads the same set.
"""

from __future__ import annotations

import fcntl
import fnmatch
import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import date, datetime, timezone

from pydantic import BaseModel, Field, model_validator

from .config import settings
from .logging_config import get_logger

log = get_logger("accepted")

SEVERITIES = ("critical", "high", "medium", "low")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
MAX_RULES = 500
WORSE_BY = 1.0  # percentage points over the reading when accepted before a finding comes back


class AcceptedRule(BaseModel):
    """One accepted risk rule, as the report's form sends it."""

    resource: str = Field("", max_length=200)  # name pattern: * and ? as wildcards; no wildcard means "contains"
    tag: str = Field("", max_length=200)  # key=value, or key alone for any value
    checks: list[str] = Field(default_factory=list, max_length=100)  # check ids; empty: every check
    account: str = Field("", max_length=200)  # account name pattern; empty: every account
    reason: str = Field(..., min_length=3, max_length=1000)
    accepted_by: str = Field(..., min_length=2, max_length=120)
    review_on: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")

    @model_validator(mode="after")
    def _names_something(self) -> AcceptedRule:
        if not self.resource.strip() and not self.tag.strip():
            raise ValueError("name the resources: a name pattern, a tag, or both")
        if self.resource.strip() in ("*", "**"):
            raise ValueError("a name pattern of * alone would accept every finding: narrow it")
        try:
            on = date.fromisoformat(self.review_on)
        except ValueError as exc:
            raise ValueError("review date is not a date") from exc
        if on <= date.today():
            raise ValueError("the review date must be in the future")
        if (on - date.today()).days > 366:
            raise ValueError("review at least once a year: pick a date within 12 months")
        return self


def _path():
    return settings.data_dir / "accepted-risks.json"


def stamp() -> tuple[int, int]:
    """Changes whenever the rules do: part of every cached report's key."""
    try:
        st = _path().stat()
    except FileNotFoundError:
        return (0, 0)
    return (st.st_mtime_ns, st.st_size)


def load() -> list[dict]:
    try:
        rules = json.loads(_path().read_text(encoding="utf-8")).get("rules") or []
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        log.warning("ignoring unreadable accepted risks file %s: %s", _path(), exc)
        return []
    return [r for r in rules if isinstance(r, dict) and r.get("id")]


def _save(rules: list[dict]) -> None:
    settings.ensure_dirs()
    fd, tmp = tempfile.mkstemp(dir=settings.data_dir, prefix=".tmp-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"rules": rules}, fh, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _path())


@contextmanager
def _locked():
    settings.ensure_dirs()
    with open(settings.data_dir / "accepted-risks.lock", "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def as_dict(rule: AcceptedRule) -> dict:
    return _clean(rule)


def _clean(rule: AcceptedRule) -> dict:
    d = rule.model_dump()
    for k in ("resource", "tag", "account", "reason", "accepted_by"):
        d[k] = d[k].strip()
    d["checks"] = sorted({c.strip() for c in d["checks"] if c.strip()})
    return d


def add(rule: AcceptedRule, ceiling: dict | None = None) -> dict:
    """Save a new rule. ``ceiling`` is the worst reading it covered when accepted: {pct, severity}."""
    with _locked():
        rules = load()
        if len(rules) >= MAX_RULES:
            raise ValueError(f"at most {MAX_RULES} accepted risk rules: remove some first")
        new = {
            "id": uuid.uuid4().hex[:10],
            **_clean(rule),
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ceiling_pct": (ceiling or {}).get("pct"),
            "ceiling_severity": (ceiling or {}).get("severity"),
        }
        rules.append(new)
        _save(rules)
        return new


def update(rule_id: str, rule: AcceptedRule, ceiling: dict | None = None) -> dict:
    """Change a rule. Its accepted reading is taken again, as the team has looked at it again."""
    with _locked():
        rules = load()
        for i, r in enumerate(rules):
            if r["id"] == rule_id:
                rules[i] = {
                    **r,
                    **_clean(rule),
                    "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "ceiling_pct": (ceiling or {}).get("pct"),
                    "ceiling_severity": (ceiling or {}).get("severity"),
                }
                _save(rules)
                return rules[i]
    raise KeyError(rule_id)


def remove(rule_id: str) -> None:
    with _locked():
        rules = load()
        kept = [r for r in rules if r["id"] != rule_id]
        if len(kept) == len(rules):
            raise KeyError(rule_id)
        _save(kept)


def _hit(pattern: str, value: str) -> bool:
    """An empty pattern names everything; one with no wildcard matches names containing it; one with
    wildcards must match the whole name, ignoring case."""
    pattern = (pattern or "").strip()
    if not pattern:
        return True
    value = value or ""
    if not any(ch in pattern for ch in "*?["):
        return pattern.lower() in value.lower()
    return re.match(fnmatch.translate(pattern), value, re.I) is not None


def _tag_matches(want: str, tags: dict | None) -> bool:
    key, _, value = want.partition("=")
    key, value = key.strip(), value.strip()
    if not tags:
        return False
    for k, v in tags.items():
        if k.lower() == key.lower() and (not value or str(v).lower() == value.lower()):
            return True
    return False


def matches(rule: dict, finding: dict) -> bool:
    """Does the rule name this finding? The review date and the reading are judged apart, by ``judge``."""
    if rule.get("checks") and finding.get("rule") not in rule["checks"]:
        return False
    if not _hit(rule.get("account", ""), finding.get("account")):
        return False
    if not _hit(rule.get("resource", ""), finding.get("res")):
        return False
    return not (rule.get("tag") and not _tag_matches(rule["tag"], finding.get("tags")))


def worse(rule: dict, finding: dict) -> str:
    """Why the finding is worse than when the rule accepted it, or ""."""
    pct, ceiling = finding.get("pct"), rule.get("ceiling_pct")
    if pct is not None and ceiling is not None and pct > ceiling + WORSE_BY:
        return f"reading {pct:.0f}%, above the {ceiling:.0f}% accepted"
    sev, was = finding.get("severity"), rule.get("ceiling_severity")
    if sev in SEV_ORDER and was in SEV_ORDER and SEV_ORDER[sev] < SEV_ORDER[was]:
        return f"now {sev}, accepted as {was}"
    return ""


def ceiling_of(found: list[dict]) -> dict:
    """The worst reading among the findings a new rule covers: the line past which they come back."""
    pcts = [f["pct"] for f in found if f.get("pct") is not None]
    sevs = [f["severity"] for f in found if f.get("severity") in SEV_ORDER]
    return {
        "pct": max(pcts) if pcts else None,
        "severity": min(sevs, key=SEV_ORDER.get) if sevs else None,
    }


def judge(findings: list[dict], rules: list[dict], today: date | None = None) -> tuple[list[dict], list[dict]]:
    """(findings still counted, findings accepted). A finding whose rule is due for review, or whose reading is
    worse than accepted, stays counted and says so in ``accepted_lapsed``."""
    today = today or date.today()
    kept, accepted = [], []
    for f in findings:
        rule = next((r for r in rules if matches(r, f)), None)
        if rule is None:
            kept.append(f)
            continue
        brief = {k: rule.get(k) for k in ("id", "reason", "accepted_by", "review_on")}
        if date.fromisoformat(rule["review_on"]) <= today:
            kept.append({**f, "accepted_lapsed": {**brief, "why": f"review was due on {rule['review_on']}"}})
            continue
        why = worse(rule, f)
        if why:
            kept.append({**f, "accepted_lapsed": {**brief, "why": why}})
            continue
        accepted.append({**f, "accepted": brief})
    return kept, accepted


def summary(rules: list[dict], accepted: list[dict], lapsed: list[dict], today: date | None = None) -> list[dict]:
    """Each rule with how many findings it covers in this report and how many have come back."""
    today = today or date.today()
    n = {}
    back = {}
    for f in accepted:
        n[f["accepted"]["id"]] = n.get(f["accepted"]["id"], 0) + 1
    for f in lapsed:
        back[f["accepted_lapsed"]["id"]] = back.get(f["accepted_lapsed"]["id"], 0) + 1
    return [
        {
            **r,
            "covers": n.get(r["id"], 0),
            "returned": back.get(r["id"], 0),
            "due": date.fromisoformat(r["review_on"]) <= today,
        }
        for r in rules
    ]
