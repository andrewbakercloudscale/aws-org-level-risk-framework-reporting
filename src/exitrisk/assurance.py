"""The Cloud Assurance Framework Report: every account scored against the selected rules.

The scan reads each account's controls (collectors/assurance.py) and the organisation's own
(collectors/assurance_org.py). This module applies the answers given in the report (which accounts
are production, internet edge or hold sensitive data, the allowed data locations, the ruleset) and
scores each account:

* each failing rule adds its severity's points (critical 40, high 15, medium 5, low 1) once,
  however many resources fail it; points combine with diminishing returns, so the score stays
  within 0 to 100: score = 100 x (1 - product of (1 - points / 100));
* a critical account (tagged, or named in the answers) counts its points 1.5 times;
* any failing critical rule sets the score to at least 80;
* a rule that could not be measured scores nothing but lowers the account's coverage, which is
  shown next to the score: a high coverage and a low score is assurance, a low coverage is not.

Nothing here calls AWS. Changing an answer or the ruleset needs no new scan.
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import ipaddress
import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from . import rulesets
from .collectors.assurance import catalog
from .filtering import AccountFilter
from .logging_config import get_logger
from .multiregion import load_region_data
from .recon import account_probes
from .resilience import _patterns, classify, owner_of

log = get_logger("assurance")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CRITICAL_FLOOR = 80
CRITICAL_ACCOUNT_WEIGHT = 1.5
RATINGS = ((80, "Critical"), (50, "High"), (20, "Medium"), (0, "Low"))
# Bucket classification tag values (lowercased) that mark sensitive data.
SENSITIVE_VALUES = ("confidential", "restricted", "sensitive", "secret", "pci", "pii", "highly", "internal-only")
# Account name parts that say non-production.
# Words in a name or OU that say it is not production, as whole words: "Non-Prod" holds "prod", so these are read
# before the production patterns. Hyphens match a space, an underscore or nothing ("nonprod", "non_prod").
# Shared core accounts (network, DNS, audit, logs) carry production traffic or its records.
PROD_DEFAULT = "prod,prd,core"
NONPROD_DEFAULT = "non-prod,pre-prod,npr,np,ppd,dev,develop,test,tst,uat,qa,sit,stg,staging,sandbox,sbx,poc,rnd,lab"
NON_PROD_MARKS = ("dev", "test", "uat", "sandbox", "sbx", "nonprod", "non-prod", "qa", "staging", "stg", "sit", "poc")
ENV_SUFFIX = re.compile(r"[-_ ]?(prd|prod|production|dev|develop|test|tst|uat|qa|sit|stg|staging|nonprod|np|sbx)$")
# Spend that means data is stored in a region.
DATA_SERVICES = (
    "Amazon Simple Storage Service", "Amazon Relational Database Service", "Amazon DynamoDB", "EC2 - Other",
    "Amazon Elastic File System", "Amazon FSx", "AWS Backup", "Amazon Redshift", "Amazon ElastiCache",
    "Amazon OpenSearch Service", "Amazon DocumentDB (with MongoDB compatibility)", "Amazon Neptune",
    "Amazon Kinesis", "Amazon Simple Queue Service", "Amazon S3 Glacier", "AWS Glue",
)  # fmt: skip
AI_MARKS = ("Bedrock", "SageMaker", "Comprehend", "Rekognition", "Textract", "Transcribe", "Polly", "Translate",
            "Lex", "Kendra", "Amazon Q", "Personalize", "Forecast", "Fraud Detector", "Lookout")  # fmt: skip
STATES = ("fail", "unknown", "pass", "na")


class AssuranceAnswers(BaseModel):
    """The questions answered in the report, all optional. Patterns are comma-separated, matched
    case-insensitively against the account name (and OU path for production)."""

    ruleset: str = Field("All rules", max_length=60)
    # A selection made in the report and not saved yet: it replaces the ruleset's rules. Severity
    # overrides apply on top of the ruleset's own.
    rules: list[Annotated[str, Field(max_length=60)]] | None = Field(None, max_length=500)
    severity: dict[Annotated[str, Field(max_length=60)], Literal["critical", "high", "medium", "low"]] = Field(
        default_factory=dict, max_length=500
    )
    production_patterns: str = Field(PROD_DEFAULT, max_length=200)
    nonproduction_patterns: str = Field(NONPROD_DEFAULT, max_length=400)
    production_accounts: str = Field("", max_length=4000)
    nonproduction_accounts: str = Field("", max_length=4000)
    edge_patterns: str = Field("edge,network,ingress,egress,dmz,perimeter,cyber,core", max_length=200)
    sensitive_patterns: str = Field("payment,card,pci,eft,pii,customer,statement", max_length=300)
    critical_patterns: str = Field("", max_length=200)
    admin_limit: int = Field(5, ge=1, le=500)
    # Countries or jurisdictions (ISO codes, EU, UK...) where data may sit; empty: the jurisdiction
    # of the busiest region.
    allowed_locations: str = Field("", max_length=200)
    required_tags: str = Field("", max_length=200)
    ai_approved: str = Field("", max_length=200)
    # Controls kept outside the accounts: a cost control platform instead of AWS Budgets, and an AI gateway that
    # every model call goes through, which logs and filters prompts and answers instead of Bedrock's own.
    cost_platform: str = Field("", max_length=100)
    ai_gateway: str = Field("", max_length=100)


def _rating(score: float) -> str:
    return next(label for floor, label in RATINGS if score >= floor)


def _matches(text: str, patterns: list[str]) -> bool:
    text = text.lower()
    return any(p in text for p in patterns)


def _tag_env(account: dict) -> str:
    tags = {re.sub(r"[^a-z]", "", k.lower()): str(v).strip().lower() for k, v in (account.get("tags") or {}).items()}
    return tags.get("environment") or tags.get("env") or tags.get("stage") or ""


def _words_re(words: list[str]) -> re.Pattern | None:
    parts = []
    for w in words:
        p = re.escape(w).replace(r"\-", r"[\s_-]?")
        parts.append(p + r"(uction)?" if w.endswith("prod") else p)
    return re.compile(rf"(^|[^a-z])({'|'.join(parts)})($|[^a-z])") if parts else None


@dataclass(frozen=True)
class ProdRule:
    """How an account is judged production: lists of accounts first, then the environment tag, then the name,
    then the OU path. In the name and OU, a non-production word wins over a production pattern."""

    prod: tuple[str, ...]
    nonprod: re.Pattern | None
    always: frozenset[str] = frozenset()
    never: frozenset[str] = frozenset()


def prod_rule(a=None, prod: list[str] | None = None) -> ProdRule:
    """The rule from a report's answers (or from production patterns alone, with the default words)."""
    if a is None:
        return ProdRule(tuple(prod or []), _words_re(_patterns(NONPROD_DEFAULT)))
    ids = lambda text: frozenset(x.strip().lower() for x in re.split(r"[,\s]+", text or "") if x.strip())  # noqa: E731
    return ProdRule(
        tuple(_patterns(a.production_patterns)),
        _words_re(_patterns(a.nonproduction_patterns)),
        ids(a.production_accounts),
        ids(a.nonproduction_accounts),
    )


def prod_text(text: str, rule: ProdRule) -> bool | None:
    """True if the text says production, False if it says otherwise, None if it says neither."""
    text = (text or "").lower()
    # A production pattern that is itself a non-production word ("dev") was chosen on purpose: it wins.
    if rule.nonprod and _matches(text, [p for p in rule.prod if rule.nonprod.search(p)]):
        return True
    if rule.nonprod and rule.nonprod.search(text):
        return False
    return True if _matches(text, list(rule.prod)) else None


def production_why(acct: dict, rule: ProdRule | list[str]) -> tuple[bool, str]:
    """(production, what decided it)."""
    if not isinstance(rule, ProdRule):
        rule = prod_rule(prod=rule)
    keys = {str(acct.get("id", "")).lower(), str(acct.get("name", "")).lower()} - {""}
    if keys & rule.never:
        return False, "listed"
    if keys & rule.always:
        return True, "listed"
    env = _tag_env(acct)
    if env:
        return env in ("prod", "production", "prd"), "tag"
    by_name = prod_text(acct.get("name", ""), rule)
    if by_name is not None:
        return by_name, "name"
    by_ou = prod_text(acct.get("ou_path", ""), rule)
    return bool(by_ou), "ou" if by_ou is not None else "none"


def is_production(acct: dict, rule: ProdRule | list[str]) -> bool:
    return production_why(acct, rule)[0]


def _sensitive_bucket(b: dict, patterns: list[str]) -> str:
    """Why the bucket counts as sensitive ("" if it does not)."""
    for k, v in (b.get("tags") or {}).items():
        if any(m in str(v).lower() for m in SENSITIVE_VALUES):
            return f"tag {k}={v}"
    if _matches(b.get("name", ""), patterns):
        return "name"
    return ""


def _covered(name: str, cover: dict | None) -> bool | None:
    if cover is None:
        return None
    if cover.get("all"):
        return True
    arn = f"arn:aws:s3:::{name}"
    return any(p.rstrip("/") == arn or p.startswith(arn + "/") for p in cover["prefixes"])


class _Account:
    """One account's rule results as the report applies them."""

    def __init__(self, raw: dict):
        self.checks: dict[str, dict] = {k: dict(v) for k, v in (raw.get("checks") or {}).items()}
        self.facts: dict = raw.get("facts") or {}

    def set(self, cid: str, status: str, items: list | None = None, note: str = "") -> None:
        out = {"status": status, "note": note}
        if status == "fail":
            items = list(items or [])
            out.update(n=len(items) or 1, ev=[str(i) for i in items[:25]])
        self.checks[cid] = out

    def fail_or_pass(self, cid: str, items: list, note: str = "") -> None:
        self.set(cid, "fail" if items else "pass", items, note)


EKS_EXPOSURE = ("eks_actuator_exposed", "eks_actuator_traffic_port", "eks_no_network_policy", "eks_literal_secrets")


def _eks_exposure(ax: _Account, outage: dict | None) -> None:
    """The Kubernetes exposure rules, from the clusters the Outage Risk Report's EKS read saw in the same scan
    (it holds the cluster sign-in). Unknown where that read did not run or could not read the cluster."""
    from .outage import PLATFORM_NS, is_platform  # here: outage imports this module

    if outage is None:
        for cid in EKS_EXPOSURE:
            ax.set(cid, "unknown", note="needs the Outage Risk Report in the same scan: it reads the clusters")
        return
    clusters = outage.get("clusters") or []
    if not clusters:
        for cid in EKS_EXPOSURE:
            ax.set(cid, "na", note="no EKS clusters")
        return
    read = [c for c in clusters if c.get("access") == "read" and c.get("exposure_access") == "read"]

    def why(c: dict) -> str:
        if c.get("access") != "read":
            return c.get("access") or "not read"
        return c.get("exposure_access") or "needs a new scan"  # scanned before these reads existed

    skipped = [f"{c['name']} ({why(c)})" for c in clusters if c not in read]
    note = f"not read: {', '.join(skipped)[:200]}" if skipped else ""
    if not read:
        for cid in EKS_EXPOSURE:
            ax.set(cid, "unknown", note=note or "clusters not read")
        return
    exposed, port_only, secrets = [], [], []
    for c in read:
        for w in c.get("workloads") or []:
            where = f"{c['name']}/{w['ns']}/{w['name']}"
            if act := w.get("actuator"):
                said = f"{where}: {act['path']} on port {act['port']}, which Service {act['service']} serves"
                said += f" (exposes {w['mgmt_expose']})" if w.get("mgmt_expose") else ""
                if act.get("routes"):
                    exposed.append(f"{said}; routed from {'; '.join(act['routes'])}")
                else:
                    port_only.append(said)
            secrets += [f"{where}: {n}" for n in w.get("secret_env") or []]
    ax.fail_or_pass("eks_actuator_exposed", exposed, note)
    ax.fail_or_pass("eks_actuator_traffic_port", port_only, note)
    ax.fail_or_pass("eks_literal_secrets", secrets, note)
    platform = [p.strip().lower() for p in PLATFORM_NS.split(",") if p.strip()]
    judged = [c for c in read if c.get("policy_access") == "read"]
    unjudged = [f"{c['name']} ({c.get('policy_access') or 'not read'})" for c in read if c not in judged]
    open_ns = [
        f"{c['name']}/{n}" for c in judged for n in c.get("open_namespaces") or [] if not is_platform(n, platform)
    ]
    if judged:
        extra = f"not judged: {', '.join(unjudged)[:200]}" if unjudged else note
        ax.fail_or_pass("eks_no_network_policy", open_ns, extra)
    else:
        ax.set("eks_no_network_policy", "unknown", note=f"not judged: {', '.join(unjudged)[:200]}")


def _edge_sources(checked: dict, accounts: list[dict], edge_p) -> tuple[dict, dict, dict, list[str]]:
    """Where traffic from the internet edge goes, across every account in the scan.

    An address is reached from the edge when an internet-facing load balancer, or any load balancer in an
    account named as an internet edge, sends to it as an IP target. A PrivateLink service is reached when an
    interface endpoint to it has such an address, or sits in an edge account. An address counts only where
    it falls in the VPC ranges of exactly one account in the scan: overlapping ranges are not guessed at.

    Returns ({ip: [from]}, {service name: [from]}, {ip: owning account id}, accounts not read)."""
    names = {x["id"]: x.get("name", "") for x in accounts}
    paths = {aid: (raw.get("facts") or {}).get("edge_paths") for aid, raw in checked.items() if aid in names}
    unread = sorted(names[aid] for aid, p in paths.items() if not p)
    nets: list[tuple] = []
    for aid, per_region in paths.items():
        for p in (per_region or {}).values():
            for c in p.get("cidrs") or []:
                with contextlib.suppress(ValueError):
                    nets.append((ipaddress.ip_network(c, strict=False), aid))

    def owner(ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        found = {aid for net, aid in nets if addr.version == net.version and addr in net}
        return next(iter(found)) if len(found) == 1 else None

    reached: dict[str, list[str]] = {}
    services: dict[str, list[str]] = {}
    for aid, per_region in paths.items():
        edge = _matches(names[aid], edge_p)
        for region, p in (per_region or {}).items():
            for t in p.get("ip_targets") or []:
                if not (t.get("public") or edge):
                    continue
                said = f"{t['lb']} in {names[aid]} ({region}{', internet-facing' if t.get('public') else ''})"
                for ip in t.get("ips") or []:
                    if owner(ip):
                        reached.setdefault(ip, []).append(said)
    for aid, per_region in paths.items():
        edge = _matches(names[aid], edge_p)
        for region, p in (per_region or {}).items():
            for e in p.get("endpoints") or []:
                via = [f for ip in e.get("ips") or [] for f in reached.get(ip, [])]
                if edge:
                    via.append(f"endpoint {e['id']} in edge account {names[aid]} ({region})")
                if via:
                    services.setdefault(e["service"], []).extend(via)
    owners = {ip: owner(ip) for ip in reached}
    return reached, services, owners, unread


def _edge_reached(
    ax: _Account, aid: str, reached: dict, services: dict, owners: dict, unread: list[str], any_source: bool
) -> None:
    """edge_reached_unfiltered for one account: its services and load balancers that traffic from the
    internet edge reaches, where nothing in front filters it."""
    cid = "edge_reached_unfiltered"
    paths = ax.facts.get("edge_paths")
    if refused := ax.facts.get("edge_paths_refused"):
        ax.set(cid, "unknown", note=f"network interfaces, target groups or VPCs not read: {refused}")
        return
    if not paths:
        ax.set(cid, "unknown", note="needs a new scan")
        return
    if not any_source:
        ax.set(cid, "unknown", note="no path from the internet edge found in this scan: include the edge accounts "
                                    "and name them in the questions (Internet edge accounts)")  # fmt: skip
        return
    why = {"none": "no security group", "not applied": "its security group is not applied to PrivateLink traffic"}
    found, seen = [], set()
    for region, p in paths.items():
        for s in p.get("services") or []:
            via = services.get(s["name"])
            if not via or (s["filter"] == "group" and not s.get("open")):
                continue
            seen.add((region, s["lb"]))
            fault = why.get(s["filter"]) or "its security group allows any address"
            found.append(f"{s['lb']} behind PrivateLink service {s['id']} ({region}): {fault}; reached from "
                         f"{'; '.join(dict.fromkeys(via))[:300]}")  # fmt: skip
        for ip, lb in (p.get("lb_ips") or {}).items():
            via = reached.get(ip)
            if not via or owners.get(ip) != aid or (region, lb["lb"]) in seen:
                continue
            if lb["filter"] == "group" and not lb.get("open"):
                continue
            seen.add((region, lb["lb"]))
            fault = "no security group" if lb["filter"] == "none" else "its security group allows any address"
            found.append(f"{lb['lb']} ({lb['type']} load balancer, {region}): {fault}; reached from "
                         f"{'; '.join(dict.fromkeys(via))[:300]}")  # fmt: skip
    notes = []
    if any(p.get("partial") for p in paths.values()):
        notes.append("not every IP target group was read")
    if unread:
        notes.append(f"accounts not read for paths: {', '.join(unread)[:200]}")
    ax.fail_or_pass(cid, found, "; ".join(notes))


def _bound_external_trust(ax: _Account, bounds: dict | None) -> None:
    """Resource control policies that stop callers outside the organisation from assuming roles make a
    role that trusts anyone trust only the organisation (and the accounts the policy lets in), and a trust
    of any other outside account unusable. Those leave the finding; the note says how many."""
    ext = ax.checks.get("external_trust") or {}
    if not bounds or not bounds.get("org_only") or ext.get("status") != "fail":
        return
    allowed = set(bounds.get("accounts") or [])
    ev = ext.get("ev") or []
    kept = [e for e in ev if (t := e.rsplit(" trusts ", 1)[-1]) != "anyone" and t in allowed]
    dropped = len(ev) - len(kept)
    note = f"{dropped} trust(s) limited to the organisation by resource control policies" if dropped else ""
    ax.set("external_trust", "fail" if kept or ext.get("n", 0) > len(ev) else "pass", kept, note)
    if ax.checks["external_trust"]["status"] == "fail":
        ax.checks["external_trust"]["n"] = ext.get("n", len(ev)) - dropped


def build_assurance(scan: dict, account_filter: AccountFilter | None = None, a: AssuranceAnswers | None = None) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    a = a or AssuranceAnswers()
    cat = catalog()
    rules = {c["id"]: c for c in cat["checks"]}
    points = cat["points"]
    ruleset = rulesets.get(a.ruleset)
    custom = a.rules is not None and a.rules != ruleset["rules"]
    enabled = [r for r in dict.fromkeys(a.rules if a.rules is not None else ruleset["rules"]) if r in rules]
    overrides = {**ruleset.get("severity", {}), **a.severity}
    severity = {r: overrides.get(r) or rules[r]["severity"] for r in enabled}
    data = scan.get("assurance") or {}
    checked = data.get("accounts") or {}
    outage_accounts = (scan.get("outage") or {}).get("accounts") or {}
    org = data.get("org") or {}
    accounts = [x for x in scan.get("accounts", []) if account_filter.matches(x["name"])]
    base = {
        "scan_id": scan.get("id"),
        "label": scan.get("label", ""),
        "scan_at": scan.get("created_at"),
        "ou": scan.get("ou"),
        "answers": a.model_dump(),
        "ruleset": {k: ruleset[k] for k in ("name", "description", "builtin")}
        | {"rules": len(enabled), "custom": custom, "of": len(rules)},
        "catalog_version": cat.get("version"),
        "scan_catalog_version": data.get("catalog_version"),
        "filter": account_filter.describe() if account_filter.active else "",
    }
    if not checked:
        return {**base, "available": False, "accounts": [], "reason": _why_empty(scan)}

    prod_p, edge_p = prod_rule(a), _patterns(a.edge_patterns)
    sens_p, crit_p = _patterns(a.sensitive_patterns), _patterns(a.critical_patterns)
    spend = _monthly_spend(scan)
    allowed = _allowed_locations(scan, a)
    regions = load_region_data()["regions"]

    reached, services, owners, unread = _edge_sources(checked, scan.get("accounts", []), edge_p)
    rows = []
    for acct in accounts:
        raw = checked.get(acct["id"])
        if raw is None:
            continue
        ax = _Account(raw)
        _eks_exposure(ax, outage_accounts.get(acct["id"]) if outage_accounts else None)
        _edge_reached(ax, acct["id"], reached, services, owners, unread, bool(reached or services))
        name = acct.get("name", "")
        production, prod_by = production_why(acct, prod_p)
        edge = _matches(name, edge_p)
        critical = classify(acct, crit_p)[0]
        buckets = ax.facts.get("buckets") or []
        sensitive = [(b, why) for b in buckets if (why := _sensitive_bucket(b, sens_p))]
        _report_time(ax, acct, a, org, scan, sensitive, production, prod_p, allowed, regions)

        results = []
        for cid in enabled:
            rule = rules[cid]
            scope = rule.get("scope", "all")
            res = ax.checks.get(cid) or {"status": "unknown", "note": "not read by this scan"}
            if scope == "production" and not production:
                res = {"status": "na", "note": "not a production account"}
            elif scope == "non_edge" and edge:
                res = {"status": "na", "note": "internet edge account"}
            elif scope == "sensitive" and not sensitive:
                res = {"status": "na", "note": "no sensitive buckets"}
            results.append({"id": cid, **res})
        rows.append(
            _score(acct, results, severity, points, critical, production, edge, sensitive, spend)
            | {"production_by": prod_by}
        )

    rows.sort(key=lambda r: (-r["score"], -r["monthly_spend"], r["name"].lower()))
    not_checked = [
        {"id": x["id"], "name": x["name"]}
        for x in accounts
        if x["id"] not in checked and x.get("status", "ACTIVE") in ("ACTIVE", "UNKNOWN")
    ]
    out = {
        **base,
        "available": True,
        "summary": _summary(rows, not_checked),
        "drivers": _drivers(rows, points),
        "areas": _areas(rows, rules, cat["areas"], severity),
        "rules": _rules(rows, rules, severity),
        "by_owner": _by_owner(rows, rules, severity),
        "next_steps": _next_steps(rows, rules, severity, account_probes(checked)),
        "accounts": rows,
        "not_checked": not_checked,
        "ownership": _ownership(accounts, checked, org),
        "organisation": _org_summary(org),
        "allowed_locations": sorted(allowed),
        "points": points,
        "build_ms": round((time.perf_counter() - started) * 1000),
    }
    return out


def _why_empty(scan: dict) -> str:
    if (scan.get("params") or {}).get("assurance"):
        return "The assurance checks ran but no account could be read: see the scan's issues."
    return "This scan did not run the Cloud Assurance Framework checks. Start a new scan with them turned on."


def _monthly_spend(scan: dict) -> dict[str, float]:
    months = len({r["month"] for r in scan.get("costs") or []}) or 1
    out: dict[str, float] = defaultdict(float)
    for r in scan.get("costs") or []:
        out[r["account_id"]] += float(r.get("amount") or 0) / months
    return out


def _allowed_locations(scan: dict, a: AssuranceAnswers) -> set[str]:
    given = {p.strip().upper() for p in a.allowed_locations.split(",") if p.strip()}
    if given:
        return given
    regions = load_region_data()["regions"]
    by: dict[str, float] = defaultdict(float)
    for r in scan.get("region_costs") or []:
        if r.get("region") in regions:
            by[r["region"]] += float(r.get("monthly") or 0)
    if not by:
        return set()
    top = max(by, key=by.get)
    return {regions[top].get("jurisdiction", ""), regions[top].get("country", "")} - {""}


def _report_time(ax: _Account, acct, a, org, scan, sensitive, production, prod_p, allowed, regions) -> None:
    """Rules judged from the answers and the organisation's facts, not read in the account itself."""
    aid, f = acct["id"], ax.facts
    unavailable = org.get("unavailable") or {}

    # Ownership.
    owner, _ = owner_of(acct)
    ax.fail_or_pass("owner_missing", [] if owner else ["no owner tag"])
    ic = org.get("identity_center")
    if not owner:
        ax.set("owner_not_found", "na", note="no owner tagged")
    elif "@" not in owner:
        ax.set("owner_not_found", "unknown", note="the owner tag is a name, not an email, so it cannot be looked up")
    elif not ic:
        ax.set("owner_not_found", "unknown", note=unavailable.get("identity_center", "Identity Center not read"))
    else:
        found = ic.get("owners", {}).get(owner.strip().lower())
        if found is None:
            ax.set("owner_not_found", "unknown", note="owner not looked up")
        else:
            ax.fail_or_pass("owner_not_found", [] if found else [owner])
    name = acct.get("name", "").lower()
    in_prod_ou = prod_text(acct.get("ou_path", ""), prod_p) is True
    marks = [m for m in NON_PROD_MARKS if re.search(rf"(^|[-_ ]){re.escape(m)}($|[-_ \d])", name)]
    ax.fail_or_pass(
        "misplaced_account", [f"named {marks[0]} in {acct.get('ou_path', '')}"] if in_prod_ou and marks else []
    )
    required = _patterns(a.required_tags)
    if required:
        have = {re.sub(r"[^a-z0-9]", "", k.lower()) for k in (acct.get("tags") or {})}
        ax.fail_or_pass("account_tags_missing", [t for t in required if re.sub(r"[^a-z0-9]", "", t) not in have])
    else:
        ax.set("account_tags_missing", "na", note="no required tags set in the report")

    # Organisation controls.
    scps = org.get("scps")
    if scps is not None and aid in scps:
        ax.fail_or_pass("scp_guardrails", scps[aid]["missing"])
        ax.fail_or_pass("scp_region_deny", [] if scps[aid]["region_deny"] else ["no region restriction"])
    else:
        why = unavailable.get("scps", "not read (needs a scan from the management account)")
        for cid in ("scp_guardrails", "scp_region_deny"):
            ax.set(cid, "unknown", note=why)
    _bound_external_trust(ax, (org.get("rcps") or {}).get(aid))
    root = org.get("root")
    if root is None:
        ax.set("central_root_off", "unknown", note=unavailable.get("root", "not read"))
    else:
        ax.fail_or_pass("central_root_off", [] if root.get("credentials") else ["central root access off"])
        if root.get("credentials") and ax.checks.get("root_mfa", {}).get("status") == "fail":
            ax.set("root_mfa", "na", note="root credentials are managed centrally for the organisation")
    if ic and "admins" in ic:
        mine = ic["admins"].get(aid, {"people": [], "direct": [], "groups": []})
        people = sorted(set(mine["people"]) | {x for x in f.get("iam_admins") or [] if x.startswith("IAM user")})
        too_many = [f"{len(people)} people: {', '.join(people[:20])}"] if len(people) > a.admin_limit else []
        ax.fail_or_pass("admin_holders", too_many, note=f"{len(people)} with administrator access")
        ax.fail_or_pass("admin_direct_user", mine["direct"])
    else:
        why = unavailable.get("identity_center", "Identity Center not read")
        ax.set("admin_holders", "unknown", note=why)
        ax.set("admin_direct_user", "unknown", note=why)
    ta = org.get("trusted_advisor")
    if ta and aid in ta:
        ax.fail_or_pass("trusted_advisor_red", ta[aid]["red"], note="from the organisation view")
        ax.fail_or_pass("trusted_advisor_yellow", ta[aid]["yellow"], note="from the organisation view")
    trails = org.get("trails") or []
    marks_org = {m for t in trails for m in (t.get("alerts") or [])}
    if (
        ax.checks.get("security_alerts_none", {}).get("status") == "fail"
        and {"root"} <= marks_org
        and (marks_org & {"aws.iam", "iam.amazonaws.com", "putuserpolicy", "attachrolepolicy"})
    ):
        ax.set("security_alerts_none", "pass", note="alarms on the organisation trail")
    delegated = org.get("delegated") or []
    aa_admin = next((d for d in delegated if "access-analyzer.amazonaws.com" in d.get("services", [])), None)
    if aa_admin and ax.checks.get("access_analyzer_off", {}).get("status") == "fail":
        ax.set(
            "access_analyzer_off",
            "pass",
            note=f"organisation analyzer delegated to {aa_admin.get('name') or aa_admin['id']}",
        )

    # Regions and data location.
    rc = [r for r in scan.get("region_costs") or [] if r["account_id"] == aid and r.get("region") in regions]
    if not scan.get("region_costs"):
        ax.set("single_region", "unknown", note="no spend by region in the scan")
        ax.set("data_location", "unknown", note="no spend by region in the scan")
    else:
        by = defaultdict(float)
        for r in rc:
            by[r["region"]] += float(r.get("monthly") or 0)
        used = [k for k, v in by.items() if v >= 1]
        ax.fail_or_pass("single_region", [f"only {used[0]}"] if production and len(used) == 1 else [])
        if not allowed:
            ax.set("data_location", "unknown", note="no allowed locations")
        else:
            stored = defaultdict(float)
            for r in rc:
                if r["service"] in DATA_SERVICES:
                    stored[r["region"]] += float(r.get("monthly") or 0)
            outside = [
                f"{k} (US${v:,.0f}/month)"
                for k, v in sorted(stored.items(), key=lambda kv: -kv[1])
                if v >= 1 and not ({regions[k].get("country"), regions[k].get("jurisdiction")} & allowed)
            ]
            ax.fail_or_pass("data_location", outside)

    # AI use.
    billed = {
        r["service"] for r in scan.get("costs") or [] if r["account_id"] == aid and float(r.get("amount") or 0) > 0
    }
    ai = sorted(s for s in billed if any(m in s for m in AI_MARKS))
    if not ai:
        ax.set("ai_unapproved", "na", note="no AI services billed")
    elif not _patterns(a.ai_approved):
        ax.set("ai_unapproved", "na", note="no accounts approved for AI set in the report")
    else:
        ax.fail_or_pass("ai_unapproved", [] if _matches(acct.get("name", ""), _patterns(a.ai_approved)) else ai)
    if gateway := a.ai_gateway.strip():
        for cid in ("bedrock_no_logging", "bedrock_no_guardrails"):
            if cid in ax.checks and ax.checks[cid]["status"] != "na":
                ax.set(cid, "na", note=f"model calls go through {gateway}, which logs and filters them")
    if (platform := a.cost_platform.strip()) and "budgets_none" in ax.checks:
        ax.set("budgets_none", "na", note=f"spend is planned and watched in {platform}")

    # Sensitive data.
    _sensitive(ax, sensitive, trails)


def _sensitive(ax: _Account, sensitive: list[tuple[dict, str]], org_trails: list[dict]) -> None:
    f = ax.facts
    cids = ("sensitive_no_versioning", "sensitive_no_lock", "sensitive_no_replication", "sensitive_no_kms",
            "sensitive_no_data_events", "sensitive_human_write")  # fmt: skip
    if f.get("buckets") is None:
        for cid in cids:
            ax.set(cid, "unknown", note="buckets not read")
        return
    if not sensitive:
        for cid in cids:
            ax.set(cid, "na", note="no bucket tagged or named as sensitive")
        return

    def failing(key: str, bad) -> tuple[list[str], bool]:
        read = [(b, w) for b, w in sensitive if b.get(key) is not None]
        return [f"{b['name']} ({w})" for b, w in read if b[key] is bad], bool(read)

    controls = (("sensitive_no_versioning", "versioning"), ("sensitive_no_lock", "lock"),
                ("sensitive_no_replication", "replicated"), ("sensitive_no_kms", "kms"))  # fmt: skip
    for cid, key in controls:
        bad = False
        items, read = failing(key, bad)
        if read:
            ax.fail_or_pass(cid, items)
        else:
            ax.set(cid, "unknown", note=f"bucket {key} not readable")
    covers = [t.get("s3_writes") for t in (f.get("trails") or []) + org_trails]
    rules = f.get("s3_rules") or {}
    gd = f.get("guardduty_s3") or {}
    unlogged, unwatched = [], []
    for b, why in sensitive:
        cov = [_covered(b["name"], c) for c in covers]
        logged = any(cov)
        if not logged:
            unlogged.append(f"{b['name']} ({why})")
        region = b.get("region", "")
        alert = gd.get(region) or any(b["name"] in p or '"object created"' in p or "putobject" in p
                                      for p in rules.get(region, []))  # fmt: skip
        if b.get("writers") and not (logged and alert):
            unwatched.append(f"{b['name']}: {', '.join(b['writers'][:5])}")
    ax.fail_or_pass("sensitive_no_data_events", unlogged)
    if any(b.get("writers") is None for b, _ in sensitive):
        ax.set("sensitive_human_write", "unknown", note="IAM policies not readable")
    else:
        ax.fail_or_pass("sensitive_human_write", unwatched)


def _points_score(failed: list[str], points: dict, weight: float) -> float:
    """An account's score from the severities of the rules it fails (see the module notes)."""
    keep = 1.0
    for sev in failed:
        keep *= 1 - min(points[sev] * weight, 99) / 100
    score = 100 * (1 - keep)
    return max(score, CRITICAL_FLOOR) if "critical" in failed else score


def _drivers(rows: list[dict], points: dict, top: int = 10) -> dict:
    """What drives the score: for each failing rule, how far the overall score would fall if it passed
    in every account, and the score and ratings once the top 2, 5 and 10 are fixed. Rules are taken in
    order of their own effect; fixing several together falls further than the sum suggests because each
    account's points compound."""
    total = sum(r["monthly_spend"] for r in rows)

    def overall(skip: set[str]) -> tuple[float, Counter]:
        scores = [
            (_points_score([f["severity"] for f in r["findings"] if f["status"] == "fail" and f["id"] not in skip],
                           points, CRITICAL_ACCOUNT_WEIGHT if r["critical"] else 1.0), r["monthly_spend"])
            for r in rows
        ]  # fmt: skip
        if total:
            score = sum(sc * w for sc, w in scores) / total
        else:
            score = sum(sc for sc, _ in scores) / len(scores) if scores else 0.0
        return score, Counter(_rating(sc) for sc, _ in scores)

    base, _ = overall(set())
    failing = Counter(f["id"] for r in rows for f in r["findings"] if f["status"] == "fail")
    sev = {f["id"]: f["severity"] for r in rows for f in r["findings"]}
    effect = sorted(((base - overall({cid})[0], cid) for cid in failing), reverse=True)[:top]
    rules = [{"id": cid, "severity": sev[cid], "accounts": failing[cid], "points": round(d, 1)} for d, cid in effect]
    fixed = []
    for n in (2, 5, 10):
        if len(effect) >= n:
            score, ratings = overall({cid for _, cid in effect[:n]})
            fixed.append({"top": n, "score": round(score, 1), "rating": _rating(score),
                          "ratings": {label: ratings.get(label, 0) for _, label in RATINGS}})  # fmt: skip
    return {"score": round(base, 1), "rules": rules, "fixed": fixed}


def _score(acct, results, severity, points, critical, production, edge, sensitive, spend) -> dict:
    weight = CRITICAL_ACCOUNT_WEIGHT if critical else 1.0
    counts = Counter(r["status"] for r in results)
    by_sev = Counter()
    failed = [severity[r["id"]] for r in results if r["status"] == "fail"]
    by_sev.update(failed)
    score = _points_score(failed, points, weight)
    applicable = counts["pass"] + counts["fail"] + counts["unknown"]
    owner, executive = owner_of(acct)
    findings = sorted(
        (r for r in results if r["status"] in ("fail", "unknown")),
        key=lambda r: (r["status"] != "fail", SEVERITY_ORDER[severity[r["id"]]], r["id"]),
    )
    return {
        "id": acct["id"],
        "name": acct["name"],
        "ou_path": acct.get("ou_path", ""),
        "owner": owner,
        "executive": executive,
        "monthly_spend": round(spend.get(acct["id"], 0.0), 2),
        "production": production,
        "edge": edge,
        "critical": critical,
        "sensitive_buckets": len(sensitive),
        "score": round(score, 1),
        "rating": _rating(score),
        "fails": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER},
        "counts": {s: counts.get(s, 0) for s in STATES},
        "coverage": round(100 * (counts["pass"] + counts["fail"]) / applicable, 1) if applicable else 100.0,
        "findings": [{**r, "severity": severity[r["id"]]} for r in findings],
        "passed": [r["id"] for r in results if r["status"] == "pass"],
        "not_applicable": [{"id": r["id"], "note": r.get("note", "")} for r in results if r["status"] == "na"],
    }


def _summary(rows: list[dict], not_checked: list[dict]) -> dict:
    total_spend = sum(r["monthly_spend"] for r in rows)
    by_spend = sum(r["score"] * r["monthly_spend"] for r in rows) / total_spend if total_spend else None
    by_count = sum(r["score"] for r in rows) / len(rows) if rows else 0.0
    score = by_spend if by_spend is not None else by_count
    ratings = Counter(r["rating"] for r in rows)
    fails = Counter()
    for r in rows:
        fails.update(r["fails"])
    measured = sum(r["counts"]["pass"] + r["counts"]["fail"] for r in rows)
    applicable = measured + sum(r["counts"]["unknown"] for r in rows)
    return {
        "accounts": len(rows),
        "not_checked": len(not_checked),
        "score": round(score, 1),
        "score_by_count": round(by_count, 1),
        "rating": _rating(score),
        "ratings": {label: ratings.get(label, 0) for _, label in RATINGS},
        "fails": {s: fails.get(s, 0) for s in SEVERITY_ORDER},
        "accounts_with_critical": sum(1 for r in rows if r["fails"]["critical"]),
        "coverage": round(100 * measured / applicable, 1) if applicable else 100.0,
        "monthly_spend": round(total_spend, 2),
    }


def _areas(rows, rules, areas, severity) -> list[dict]:
    out = []
    for key, meta in areas.items():
        ids = [cid for cid in severity if rules[cid]["area"] == key]
        if not ids:
            continue
        fail = unknown = passed = 0
        failing_accounts = set()
        for r in rows:
            for fnd in r["findings"]:
                if fnd["id"] in ids:
                    if fnd["status"] == "fail":
                        fail += 1
                        failing_accounts.add(r["id"])
                    else:
                        unknown += 1
            passed += sum(1 for p in r["passed"] if p in ids)
        measured = fail + passed
        out.append({
            "id": key, "label": meta["label"], "concern": meta["concern"], "rules": len(ids), "fails": fail,
            "unknown": unknown, "passes": passed, "accounts_failing": len(failing_accounts),
            "pass_rate": round(100 * passed / measured, 1) if measured else None,
        })  # fmt: skip
    return sorted(out, key=lambda x: (x["pass_rate"] if x["pass_rate"] is not None else 101, x["label"]))


def _rules(rows, rules, severity) -> list[dict]:
    stats: dict[str, dict] = {cid: {"fail": 0, "unknown": 0, "pass": 0, "na": 0, "resources": 0, "accounts": []}
                              for cid in severity}  # fmt: skip
    for r in rows:
        for fnd in r["findings"]:
            s = stats[fnd["id"]]
            s[fnd["status"]] += 1
            if fnd["status"] == "fail":
                s["resources"] += fnd.get("n", 1)
                s["accounts"].append(
                    {"id": r["id"], "name": r["name"], "n": fnd.get("n", 1), "ev": fnd.get("ev", [])[:5]}
                )
        for p in r["passed"]:
            stats[p]["pass"] += 1
        for na in r["not_applicable"]:
            stats[na["id"]]["na"] += 1
    out = []
    for cid, s in stats.items():
        rule = rules[cid]
        s["accounts"].sort(key=lambda x: -x["n"])
        out.append({
            "id": cid, "title": rule["title"], "area": rule["area"], "severity": severity[cid],
            "catalog_severity": rule["severity"], "scope": rule.get("scope", "all"), "why": rule["why"],
            "attack": rule.get("attack", ""), "fix": rule["fix"], "refs": rule.get("refs") or [], **s,
        })  # fmt: skip
    return sorted(out, key=lambda x: (x["fail"] == 0, SEVERITY_ORDER[x["severity"]], -x["fail"], x["id"]))


NO_OWNER = "No owner tag"
OWNER_SEVERITIES = ("critical", "high")


def _by_owner(rows: list[dict], rules: dict, severity: dict) -> dict:
    """Each owner's actions: the critical and high rules failing in their accounts, one action per rule, with the
    accounts and items it covers. The owner is the account's owner tag; accounts with none are one group."""
    groups: dict[str, dict[str, list]] = {}
    for r in rows:
        for f in r["findings"]:
            if f["status"] == "fail" and severity[f["id"]] in OWNER_SEVERITIES:
                groups.setdefault(r["owner"] or NO_OWNER, {}).setdefault(f["id"], []).append((r, f))
    out = []
    for owner, by_rule in groups.items():
        actions = []
        for cid, mine in by_rule.items():
            mine.sort(key=lambda x: (-x[1].get("n", 1), x[0]["name"].lower()))
            rule = rules[cid]
            actions.append(
                {
                    "rule": cid,
                    "title": rule["title"],
                    "severity": severity[cid],
                    "items": sum(f.get("n", 1) for _, f in mine),
                    "accounts": [
                        {"id": r["id"], "name": r["name"], "n": f.get("n", 1), "ev": (f.get("ev") or [])[:3]}
                        for r, f in mine
                    ],  # fmt: skip
                    "why": rule["why"],
                    "attack": rule.get("attack", ""),
                    "fix": rule["fix"],
                }
            )
        actions.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], -len(x["accounts"]), x["title"]))
        out.append(
            {
                "owner": owner,
                "tagged": owner != NO_OWNER,
                "critical": sum(len(x["accounts"]) for x in actions if x["severity"] == "critical"),
                "high": sum(len(x["accounts"]) for x in actions if x["severity"] == "high"),
                "accounts": sorted({a["name"] for x in actions for a in x["accounts"]}, key=str.lower),
                "actions": actions,
            }
        )
    out.sort(key=lambda o: (-o["critical"], -o["high"], o["owner"].lower()))
    return {"owners": out, "untagged_accounts": sum(1 for r in rows if not r["owner"])}


NEXT_TOP = 10
# Risk points per failing rule per account, the same as the owner bubble chart: a non-production account a tenth.
NEXT_POINTS = {"critical": 100, "high": 10, "medium": 1, "low": 0.1}
NONPROD_SHARE = 0.1
# What moves an action up a leader's list, beyond its risk points: an attacker finds an exposure first, an edge
# account is the way in, a critical account and sensitive data cost the most when breached, and access is how
# a foothold spreads.
NEXT_BOOST = {
    "exposure": (2.0, "reachable from outside"),
    "access": (1.5, "how an attacker spreads"),
    "edge": (1.5, "internet edge account"),
    "critical": (1.5, "critical account"),
    "sensitive": (1.5, "sensitive data"),
    "chain": (1.5, "breaks an attack chain"),
}
# Someone probing the account now: an exposure there (or, for refused API calls, an access weakness) goes first.
PROBED_BOOST = 3.0
# An edge account matters more for the rules about the way in and seeing it used.
EDGE_AREAS = ("exposure", "access", "detection", "logging")
NO_LEADER = "No owner or executive tag"
# An attack chain: in one production account, a way in, a way to spread and something worth taking, each a
# critical or high rule failing (or sensitive buckets as the prize). Detection gaps say no one would notice.
CHAIN_SEVERITIES = ("critical", "high")
CHAIN_STEPS = {"in": ("exposure",), "spread": ("access",), "prize": ("data", "sensitive"),
               "unseen": ("detection", "logging")}  # fmt: skip


def _chains(rows: list[dict], rules: dict, probes: dict) -> list[dict]:
    """Production accounts where the internet can get in, spread and reach data: one story, not three findings."""
    out = []
    for r in rows:
        if not r["production"]:
            continue
        steps: dict[str, list[dict]] = {k: [] for k in CHAIN_STEPS}
        for f in r["findings"]:
            if f["status"] != "fail" or f["severity"] not in CHAIN_SEVERITIES:
                continue
            for k, areas in CHAIN_STEPS.items():
                if rules[f["id"]]["area"] in areas:
                    steps[k].append({"rule": f["id"], "title": rules[f["id"]]["title"], "severity": f["severity"]})
        prize = steps["prize"] or ([{"rule": "", "title": f"{r['sensitive_buckets']} sensitive bucket"
                                     f"{'s' if r['sensitive_buckets'] != 1 else ''}", "severity": ""}]
                                   if r["sensitive_buckets"] else [])  # fmt: skip
        if not (steps["in"] and steps["spread"] and prize):
            continue
        p = probes.get(r["id"]) or {}
        out.append({"id": r["id"], "name": r["name"], "leader": r["executive"] or r["owner"] or NO_LEADER,
                    "critical": r["critical"], "in": steps["in"], "spread": steps["spread"], "prize": prize,
                    "unseen": steps["unseen"], "probed": p.get("network", []) + p.get("api", [])})  # fmt: skip
    out.sort(key=lambda c: (not c["probed"], not c["critical"], -len(c["in"]) - len(c["spread"]), c["name"].lower()))
    return out


def _next_steps(rows: list[dict], rules: dict, severity: dict, probes: dict | None = None,
                top: int = NEXT_TOP) -> dict:  # fmt: skip
    """What should each leader do next: up to ten failing rules per leader, most important first. A leader is the
    account's executive tag, else its owner tag. An action is one rule across all the leader's accounts it fails
    in; its risk points are the owner chart's (100 critical, 10 high, 1 medium, a tenth low, a non-production
    account a tenth), raised in a production account when the rule is internet exposure or access, the account
    is critical, an edge account (for the way-in and detection rules) or holds sensitive data (for the data
    rules), or the rule is a step of an attack chain. An exposure in an account someone is probing now (an
    access weakness, when the probing is refused API calls) goes to the top. Says how much of the leader's
    risk points the list removes."""
    probes = probes or {}
    chains = _chains(rows, rules, probes)
    in_chain = {(c["id"], s["rule"]) for c in chains for k in ("in", "spread", "prize", "unseen") for s in c[k]}
    groups: dict[str, dict] = {}
    for r in rows:
        who = r["executive"] or r["owner"]
        key = " ".join(who.casefold().split()) if who else ""
        g = groups.setdefault(key, {"leader": who or NO_LEADER, "tagged": bool(who), "owners": set(),
                                    "accounts": set(), "rules": {}, "probed": []})  # fmt: skip
        if r["owner"] and r["owner"] != who:
            g["owners"].add(r["owner"])
        if p := probes.get(r["id"]):
            g["probed"].append({"id": r["id"], "name": r["name"], **p})
        for f in r["findings"]:
            if f["status"] != "fail":
                continue
            g["accounts"].add(r["name"])
            g["rules"].setdefault(f["id"], []).append((r, f))
    out = []
    for g in groups.values():
        actions = []
        for cid, mine in g["rules"].items():
            rule, sev = rules[cid], severity[cid]
            area = rule["area"]
            pts = prio = 0.0
            why: set[str] = set()
            probed: list[str] = []
            for r, _ in mine:
                p = NEXT_POINTS[sev] * (1 if r["production"] else NONPROD_SHARE)
                boost = 1.0
                data = area in ("data", "sensitive") and r["sensitive_buckets"] > 0
                flags = [area == "exposure", area == "access", r["edge"] and area in EDGE_AREAS, r["critical"],
                         data, (r["id"], cid) in in_chain]  # fmt: skip
                for on, (x, text) in zip(flags, NEXT_BOOST.values(), strict=True):
                    if on and r["production"]:
                        boost *= x
                        why.add(text)
                signs = probes.get(r["id"]) or {}
                seen = signs.get("network") if area == "exposure" else signs.get("api") if area == "access" else None
                if seen:
                    boost *= PROBED_BOOST
                    probed += [f"{r['name']}: {s}" for s in seen[:2]]
                pts += p
                prio += p * boost
            mine.sort(key=lambda x: (not x[0]["production"], -x[1].get("n", 1), x[0]["name"].lower()))
            prod = sum(1 for r, _ in mine if r["production"])
            if prod:
                why.add(f"{prod} production account{'s' if prod != 1 else ''}")
            if probed:
                why.add("being probed now")
            actions.append({
                "rule": cid, "title": rule["title"], "severity": sev, "area": area,
                "points": round(pts, 1), "priority": round(prio, 1), "probed": probed[:3],
                "why_first": sorted(why, key=lambda t: (t != "being probed now", not t[0].isdigit(), t)),
                "items": sum(f.get("n", 1) for _, f in mine),
                "accounts": [{"id": r["id"], "name": r["name"], "production": r["production"], "n": f.get("n", 1),
                              "ev": (f.get("ev") or [])[:3]} for r, f in mine],
                "why": rule["why"], "attack": rule.get("attack", ""), "fix": rule["fix"],
            })  # fmt: skip
        if not actions:
            continue
        actions.sort(key=lambda x: (not (x["probed"] and x["area"] == "exposure" and x["severity"] in CHAIN_SEVERITIES),
                                    -x["priority"], SEVERITY_ORDER[x["severity"]],
                                    -len(x["accounts"]), x["title"]))  # fmt: skip
        total = sum(x["points"] for x in actions)
        chosen = actions[:top]
        removed = sum(x["points"] for x in chosen)
        out.append({
            "leader": g["leader"], "tagged": g["tagged"], "owners": sorted(g["owners"], key=str.lower),
            "accounts": len(g["accounts"]), "points": round(total, 1), "rules": len(actions),
            "share": round(100 * removed / total, 1) if total else 0.0,
            "probed": g["probed"], "chains": sum(1 for c in chains if c["leader"] == g["leader"]),
            "actions": [x | {"rank": i} for i, x in enumerate(chosen, 1)],
        })  # fmt: skip
    out.sort(key=lambda x: (not x["tagged"], -x["points"], x["leader"].lower()))
    return {"leaders": out, "top": top, "chains": chains, "probed": len({p["id"] for x in out for p in x["probed"]}),
            "boosts": {k: v[1] for k, v in NEXT_BOOST.items()}}  # fmt: skip


def previous_scan(scans: list[dict], scan_id: str) -> str | None:
    """The scan just before this one of the same OU and mode with the Cloud Assurance checks (scan list entries)."""
    cur = next((s for s in scans if s["id"] == scan_id), None)
    if not cur:
        return None
    at = cur.get("created_at") or ""
    earlier = [s for s in scans if s.get("assurance") and s["id"] != scan_id and s.get("ou") == cur.get("ou")
               and s.get("mode") == cur.get("mode") and s.get("status") in ("complete", "partial")
               and (s.get("created_at") or "") < at]  # fmt: skip
    return max(earlier, key=lambda s: s.get("created_at") or "")["id"] if earlier else None


def next_progress(report: dict, before: dict | None) -> None:
    """Each leader's movement since the scan before: the actions closed (a rule that failed in one of their
    accounts and now passes there), the actions new since then, and their risk points then and now. Only
    accounts read in both scans count, so an account added or left out moves nothing."""
    nxt = report.get("next_steps")
    if not nxt or not before or not before.get("available"):
        return
    was = {a["id"]: {f["id"] for f in a["findings"] if f["status"] == "fail"} for a in before["accounts"]}
    now = {a["id"]: a for a in report["accounts"]}
    leader = {a["id"]: a["executive"] or a["owner"] or NO_LEADER for a in report["accounts"]}
    sev = {r["id"]: r["severity"] for r in report.get("rules") or []}
    titles = {r["id"]: r["title"] for r in report.get("rules") or []}
    both = [aid for aid in now if aid in was]
    for x in nxt["leaders"]:
        mine = [aid for aid in both if leader[aid] == x["leader"]]
        closed: dict[str, list[str]] = {}
        then = 0.0
        for aid in mine:
            a = now[aid]
            failing = {f["id"] for f in a["findings"] if f["status"] == "fail"}
            share = 1 if a["production"] else NONPROD_SHARE
            then += sum(NEXT_POINTS[sev[c]] * share for c in was[aid] if c in sev)
            for c in was[aid] - failing:
                if c in sev:
                    closed.setdefault(c, []).append(a["name"])
        nowp = sum(NEXT_POINTS[sev[f["id"]]] * (1 if now[aid]["production"] else NONPROD_SHARE)
                   for aid in mine for f in now[aid]["findings"]
                   if f["status"] == "fail" and f["id"] in sev)  # fmt: skip
        new = 0
        for act in x["actions"]:
            fresh = [a["name"] for a in act["accounts"] if a["id"] in was and act["rule"] not in was[a["id"]]]
            act["new_in"] = fresh
            new += bool(fresh)
        x["progress"] = {
            "closed": sorted(
                ({"rule": c, "title": titles.get(c, c), "severity": sev[c], "accounts": n} for c, n in closed.items()),
                key=lambda c: (SEVERITY_ORDER[c["severity"]], -len(c["accounts"])),
            ),  # fmt: skip
            "new": new,
            "points_then": round(then, 1),
            "points_now": round(nowp, 1),
            "accounts": len(mine),
        }
    nxt["since"] = {"scan_id": before.get("scan_id"), "scan_at": before.get("scan_at"), "label": before.get("label")}


def _stem(name: str) -> str:
    n = name.lower().strip()
    for prefix in ("aws-", "acc-", "account-"):
        if n.startswith(prefix):
            n = n[len(prefix) :]
    for env in ("prd-", "prod-", "dev-", "tst-", "test-", "uat-", "qa-", "np-", "nonprod-", "sbx-"):
        if n.startswith(env):
            n = n[len(env) :]
    return ENV_SUFFIX.sub("", n)


def _ownership(accounts: list[dict], checked: dict, org: dict) -> dict:
    """Each account's owner, whether it checks out, and a proposed owner where it does not: the
    owner most of its sibling accounts (same name without the environment) have."""
    found = ((org.get("identity_center") or {}).get("owners")) or {}
    owners = {x["id"]: owner_of(x)[0] for x in accounts}

    def status(owner: str) -> str:
        if not owner:
            return "missing"
        if "@" in owner and owner.strip().lower() in found:
            return "verified" if found[owner.strip().lower()] else "not found"
        return "unverified"

    stems: dict[str, Counter] = defaultdict(Counter)
    ous: dict[str, Counter] = defaultdict(Counter)
    for x in accounts:
        o = owners[x["id"]]
        if status(o) in ("verified", "unverified"):
            stems[_stem(x["name"])][o] += 1
            ous[x.get("ou_path", "")][o] += 1
    rows = []
    for x in accounts:
        o = owners[x["id"]]
        st = status(o)
        proposal, basis = "", ""
        if st in ("missing", "not found"):
            cands = stems.get(_stem(x["name"]))
            in_ou = ous.get(x.get("ou_path", ""))
            if cands:
                proposal, n = cands.most_common(1)[0]
                basis = f"owner of {n} related account{'s' if n != 1 else ''} ({_stem(x['name'])})"
            elif in_ou and in_ou.most_common(1)[0][1] * 2 >= sum(in_ou.values()):
                # Only when one owner holds at least half of the OU's owned accounts: else it is a guess.
                proposal, n = in_ou.most_common(1)[0]
                basis = f"owner of {n} of the accounts in {x.get('ou_path', '')}"
        rows.append({"id": x["id"], "name": x["name"], "owner": o, "status": st, "proposal": proposal,
                     "basis": basis, "checked": x["id"] in checked})  # fmt: skip
    counts = Counter(r["status"] for r in rows)
    return {
        "rows": sorted(rows, key=lambda r: (r["status"] in ("verified", "unverified"), r["name"].lower())),
        "counts": dict(counts),
        "directory": bool(found) or "identity_center" in org,
    }


def _org_summary(org: dict) -> dict:
    ic = org.get("identity_center") or {}
    return {
        "read": bool(org),
        "admin_permission_sets": ic.get("admin_sets", []),
        "delegated": org.get("delegated") or [],
        "root": org.get("root"),
        "trails": [{k: t.get(k) for k in ("name", "home", "logging")} for t in org.get("trails") or []],
        "trusted_advisor_org": "trusted_advisor" in org,
        "unavailable": org.get("unavailable") or {},
    }


# ---------------------------------------------------------------------------------- exports


OWNER_TAG = "Owner"


def ownership_export(report: dict, approved: dict[str, str], tag: str = OWNER_TAG) -> dict:
    """The approved owner changes as a CSV and as AWS CLI commands, for an administrator to apply.
    The console never writes to AWS: ``approved`` is {account id: new owner}."""
    names = {r["id"]: r for r in report.get("ownership", {}).get("rows", [])}
    rows = [(aid, names[aid]["name"], names[aid]["owner"], new.strip()) for aid, new in approved.items()
            if aid in names and new.strip()]  # fmt: skip
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["account_id", "account_name", "current_owner", "new_owner"])
    w.writerows(rows)
    safe_tag = re.sub(r"[^\w.:/=+@-]", "", tag) or OWNER_TAG
    lines = [
        "# Apply in the management account with a role allowed organizations:TagResource.",
        "# Review every line first: this changes the account's owner tag.",
    ]
    for aid, name, _old, new in rows:
        value = new.replace("'", "")
        lines.append(
            f"aws organizations tag-resource --resource-id {aid} --tags 'Key={safe_tag},Value={value}'  # {name}"
        )
    return {"csv": buf.getvalue(), "commands": "\n".join(lines) + "\n", "count": len(rows)}


def evidence(report: dict) -> dict:
    """The report as an evidence record, with a SHA-256 of its canonical JSON to show it is unchanged."""
    body = {k: v for k, v in report.items() if k != "build_ms"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "algorithm": "SHA-256 of the report JSON with sorted keys and no spaces",
        "report": body,
    }
