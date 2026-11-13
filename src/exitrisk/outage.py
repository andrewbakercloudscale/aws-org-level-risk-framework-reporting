"""The Outage Risk Report: what is likely to fail at the next peak, by account, and where to start.

The scan reads measures in each account (collectors/outage.py). This module applies the answers
given in the report and judges each one:

* a capacity measure is critical at the critical threshold now, or if it fills before the peak; high
  if it would pass its limit at the expected peak load (usage that rises with traffic, multiplied by
  the expected load), or fills within 30 days after the peak; medium above the warning threshold;
* an event (throttling, rejected calls, an OOMKill) already happened in the lookback window, and a
  config finding is a setting that fails at load: both carry the rule's own severity;
* outside production everything is one level lower, as the peak is a production event. Filter to
  production with the report's filter to leave the rest out altogether.

Accounts score as in the Cloud Assurance Report: each rule failed adds its severity's points once,
with diminishing returns, and a critical sets the score to at least 80.

Nothing here calls AWS. Changing an answer needs no new scan.
"""

from __future__ import annotations

import csv
import fnmatch
import io
import math
import re
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources

import yaml
from pydantic import BaseModel, Field

from . import accepted as accepted_risks
from .assurance import NONPROD_DEFAULT, PROD_DEFAULT, _monthly_spend, _points_score, _rating, prod_rule, production_why
from .filtering import AccountFilter
from .issues import FAILURE_KINDS, failure_kind
from .logging_config import get_logger
from .outage_views import build_views, label_services
from .resilience import _patterns, owner_of

log = get_logger("outage")

SEVERITIES = ("critical", "high", "medium", "low")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
KEEP_PCT = 30.0  # the collector keeps no measure under this
AFTER_PEAK_DAYS = 30  # filling this soon after the peak is still worth doing before it
MAX_FINDINGS = 4000  # sent to the page, worst first; the counts always cover every finding
NOT_MEASURED = "Not measured"  # no check could read the account: no score, and first in the list, not "Low"
# Namespaces of the cluster's shared tooling, whose workloads its platform team owns: not judged in each account,
# where every account would repeat them. Wildcards; Kubernetes's own and the AWS add-ons are covered by kube-*, aws-*
# and amazon-*.
PLATFORM_NS = (
    "kube-*,amazon-*,aws-*,*-system,*-operator,argocd,argo-*,cert-manager,kyverno,keda,karpenter,external-dns,"
    "external-secrets,metrics-server,velero,vault*,ingress-*,cattle-*,fleet-*,calico*,tigera*,istio-*,linkerd*"
)


@lru_cache(maxsize=1)
def catalog() -> dict:
    """The rules and the published evidence, data/outage.yaml."""
    return yaml.safe_load(resources.files("exitrisk").joinpath("data/outage.yaml").read_text(encoding="utf-8"))


def black_friday(today: date | None = None) -> date:
    """The next Black Friday: the day after the fourth Thursday of November."""
    today = today or date.today()
    for year in (today.year, today.year + 1):
        first = date(year, 11, 1)
        thursday = first + timedelta(days=(3 - first.weekday()) % 7)
        friday = thursday + timedelta(days=22)
        if friday >= today:
            return friday
    raise AssertionError("unreachable")


class OutageAnswers(BaseModel):
    """The questions answered in the report, all optional."""

    # The peak; empty: the next Black Friday.
    peak_date: str = Field("", pattern=r"^(\d{4}-\d{2}-\d{2})?$")
    # Expected peak load as a multiple of the highest hourly load in the last 35 days, which holds a
    # month-end. An assumption until replaced with the measured ratio from last year.
    peak_multiplier: float = Field(2.0, ge=1.0, le=3.0)
    freeze_days: int = Field(14, ge=0, le=90)
    warn_pct: int = Field(70, ge=40, le=95)
    critical_pct: int = Field(90, ge=60, le=100)
    production_patterns: str = Field(PROD_DEFAULT, max_length=200)
    nonproduction_patterns: str = Field(NONPROD_DEFAULT, max_length=400)
    production_accounts: str = Field("", max_length=4000)
    nonproduction_accounts: str = Field("", max_length=4000)
    cpu_request_floor_m: int = Field(100, ge=1, le=4000)
    memory_limit_floor_mi: int = Field(256, ge=1, le=65536)
    platform_namespaces: str = Field(PLATFORM_NS, max_length=1000)
    # When customers use the service, local time, every day: maintenance and backups should miss it.
    busy_hours: str = Field("06:00-22:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-4]):[0-5]\d$")
    utc_offset: float = Field(2.0, ge=-12, le=14)  # hours local time is ahead of UTC (South Africa: 2)


def is_platform(ns: str, patterns: list[str]) -> bool:
    """Whether a namespace is the platform team's, by the answered wildcards (``_patterns``, lower case)."""
    return any(fnmatch.fnmatchcase(str(ns).lower(), p) for p in patterns)


def _lower(sev: str) -> str:
    return SEVERITIES[min(SEV_ORDER[sev] + 1, len(SEVERITIES) - 1)]


def judge_capacity(row: dict, a: OutageAnswers, days_to_peak: int) -> tuple[str | None, float | None, str]:
    """(severity or None, percent at peak, why) of one capacity measure."""
    pct = row.get("pct") or 0.0
    peak = pct * a.peak_multiplier if row.get("load") else pct
    days = row.get("days")
    if days is not None and days <= days_to_peak:
        return "critical", round(peak, 1), f"at its limit in about {days:.0f} days, before the peak"
    if pct >= a.critical_pct:
        return "critical", round(peak, 1), f"at {pct:.0f}% already"
    if row.get("load") and peak >= 100:
        return "high", round(peak, 1), f"{pct:.0f}% now, {peak:.0f}% at {a.peak_multiplier:g}x load"
    if days is not None and days <= days_to_peak + AFTER_PEAK_DAYS:
        return "high", round(peak, 1), f"at its limit in about {days:.0f} days, soon after the peak"
    if peak >= a.warn_pct:
        return (
            "medium",
            round(peak, 1),
            f"{pct:.0f}% now" + (f", {peak:.0f}% at {a.peak_multiplier:g}x load" if row.get("load") else ""),
        )
    return None, round(peak, 1), ""


def judge_burstable(row: dict, a: OutageAnswers) -> tuple[str, str]:
    """(severity, why) of a burstable size, against the expected peak load: high when the peak would
    spend its credits and hold it to its baseline, medium when it bills for the surplus instead or
    nothing says how busy it is, low when it stays under its baseline even at the peak."""
    kind, base, cpu, unlimited = row.get("type", ""), row.get("baseline"), row.get("cpu"), row.get("unlimited")
    mode = {True: "unlimited credits", False: "standard credits"}.get(unlimited, "credit mode not known")
    credits = row.get("credits")
    floor = f" {base:g}%" if base else " its baseline"
    if credits is not None and credits < 5 and unlimited is not True:
        return "high", f"{kind}, {mode}: CPU credits fell to {credits:g}; at zero it is held to{floor} CPU"
    if cpu is None or not base:
        return "medium", f"{kind}, {mode}: no CPU figure to compare with its baseline"
    peak = cpu * a.peak_multiplier
    said = f"{kind}, {mode}: busiest hour {cpu:g}% CPU, {peak:.0f}% at {a.peak_multiplier:g}x load, baseline{floor}"
    if peak <= base:
        return "low", f"{said}; under it, but network and EBS bandwidth still burst"
    if unlimited:
        return "medium", f"{said}; above it, it keeps running and bills the surplus credits"
    return "high", f"{said}; above it the credits drain, then it is held to the baseline"


DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEK = 7 * 1440


def _minute(text: str) -> int:
    h, m = text.split(":")
    return int(h) * 60 + int(m)


def _window_minutes(window: str) -> list[int] | None:
    """UTC minutes of the week a window covers: "sun:23:00-mon:00:30" weekly, "02:00-02:30" every day.
    None for anything not in either form."""
    try:
        start, end = window.strip().lower().split("-")
        if start[:3] in DAYS:
            a = DAYS.index(start[:3]) * 1440 + _minute(start[4:])
            b = DAYS.index(end[:3]) * 1440 + _minute(end[4:])
            span = (b - a) % WEEK or WEEK
            return [(a + i) % WEEK for i in range(span)]
        a, b = _minute(start), _minute(end)
        span = (b - a) % 1440 or 1440
        return [(day * 1440 + a + i) % WEEK for day in range(7) for i in range(span)]
    except (ValueError, IndexError):
        return None


def busy_overlap(window: str, a: OutageAnswers) -> int | None:
    """Minutes of the window in a week that fall in the busy hours, local time; None if unreadable."""
    minutes = _window_minutes(window)
    if minutes is None:
        return None
    s, e = (_minute(x) for x in a.busy_hours.split("-"))
    shift = round(a.utc_offset * 60)
    hit = 0
    for m in minutes:
        local = (m + shift) % 1440
        hit += (s <= local < e) if s <= e else (local >= s or local < e)
    return hit


def _local(window: str, a: OutageAnswers) -> str:
    """The window in local time, for the finding's text: "Sun 01:00 to Sun 01:30", or "04:00 to 04:30"."""
    shift = round(a.utc_offset * 60)

    def one(part: str) -> str:
        part = part.strip().lower()
        if part[:3] in DAYS:
            t = (DAYS.index(part[:3]) * 1440 + _minute(part[4:]) + shift) % WEEK
            return f"{DAYS[t // 1440].title()} {t % 1440 // 60:02d}:{t % 60:02d}"
        t = (_minute(part) + shift) % 1440
        return f"{t // 60:02d}:{t % 60:02d}"

    try:
        start, end = window.split("-")
        return f"{one(start)} to {one(end)}"
    except (ValueError, IndexError):
        return window


def judge_windows(row: dict, a: OutageAnswers) -> str | None:
    """Why the database's maintenance or backup window is in the busy hours, or None when neither is.
    A backup counts only on a single-AZ instance: Multi-AZ backs up from the standby, Aurora continuously."""
    said = []
    tz = f"UTC{a.utc_offset:+g}"
    maint = row.get("maintenance") or ""
    if maint and busy_overlap(maint, a):
        said.append(f"maintenance window {_local(maint, a)} ({tz}), {maint} UTC")
    backup = row.get("backup") or ""
    if backup and not row.get("multi_az") and busy_overlap(backup, a):
        said.append(f"daily backup {_local(backup, a)} ({tz}) on a single-AZ instance")
    if not said:
        return None
    return "; ".join(said) + f"; busy hours {a.busy_hours}"


BURSTABLE_RULES = {"ec2_burstable", "rds_burstable", "cache_burstable", "search_burstable", "msk_burstable"}


def _judge(row: dict, rule: dict, a: OutageAnswers, peak: date, days_to_peak: int, production: bool) -> dict | None:
    """The finding this row makes, or None."""
    if (rule.get("prod_only") or row.get("prod_only")) and not production:  # a row's own: under production's bar
        return None
    at_peak = None
    if rule["kind"] == "capacity":
        sev, at_peak, why = judge_capacity(row, a, days_to_peak)
        if not sev:
            return None
        if rule["id"] == "eks_nodegroup_max" and row.get("min") is not None and row.get("min") == row.get("limit"):
            sev, why = "medium", f"fixed at {row['limit']} node(s): minimum and maximum are the same"
    else:
        sev, why = row.get("sev") or rule["severity"], row.get("note", "")  # a row may know better
        if rule["id"] in BURSTABLE_RULES:
            sev, why = judge_burstable(row, a)
        elif rule["id"] in ("rds_maintenance", "ec2_event"):
            ends = date.fromisoformat(row["ends"])
            if ends > peak + timedelta(days=7):
                return None
            why = f"applies on {row['ends']}: {row.get('note', '')}"
        elif rule["id"] == "rds_busy_window":
            why = judge_windows(row, a)
            if not why:
                return None
        elif rule["id"] in ("cert_expiry", "iam_cert_expiry", "domain_expiry"):
            ends = date.fromisoformat(row["ends"])
            if ends > peak + timedelta(days=7):
                return None
            if row.get("auto"):  # AWS renews it: only worth a look when it has not by now
                if (ends - date.today()).days > 30:
                    return None
                sev = "medium"
            why = f"expires {row['ends']}, {row.get('note', '')}"
        elif row.get("used") is not None and row.get("unit"):
            why = f"{row['used']:,} {row['unit']}" + (f"; {why}" if why else "")
    if not production:
        sev = _lower(sev)
    return {
        "rule": rule["id"],
        "res": row["res"],
        "region": row["region"],
        "severity": sev,
        "why": why,
        "pct": row.get("pct"),
        "at_peak": at_peak,
        "used": row.get("used"),
        "limit": row.get("limit"),
        "unit": row.get("unit", ""),
        "days": row.get("days"),
        "hard": bool(row.get("hard")),
        "note": row.get("note", ""),
        "basis": limit_basis(row) if rule["kind"] == "capacity" else "",
    }


def _n(v: float) -> str:
    return f"{v:,.0f}" if float(v).is_integer() or abs(v) >= 100 else f"{v:,.1f}"


def limit_basis(row: dict) -> str:
    """Which limit, and the reading set against it: what a reader needs to check the finding."""
    if row.get("used") is None or row.get("limit") is None:
        return ""
    unit = f" {row['unit']}" if row.get("unit") else ""
    which = (
        f" (Service Quotas {row['qcode']}{', not adjustable' if row.get('hard') else ''})" if row.get("qcode") else ""
    )
    text = f"Limit {_n(row['limit'])}{unit}{which}. Highest {_n(row['used'])}{unit}"
    if row.get("peak_at"):
        at = datetime.fromisoformat(row["peak_at"])
        at = at.astimezone(timezone.utc) if at.tzinfo else at
        text += f" on {at:%Y-%m-%d} at {at:%H:%M} UTC"
    if row.get("metric"):
        text += f", from CloudWatch {row['metric']}: {row.get('read', '')}"
    return text + "."


THROTTLED_PCT = 5.0  # share of a container's CPU periods throttled over the window that is worth a look
THROTTLED_HIGH_PCT = 25.0
RESTARTS_FLAG = 3  # container restarts over the window
HPA_LATE_PCT = 90  # a pod autoscaler that waits until this share of the CPU limit is throttled before it scales
BURST_PCT = 80  # throttled while the highest 5-minute CPU stays under this share of the limit: in bursts
LIVENESS_TIMEOUT_MIN = 2  # seconds: a liveness check given less fails on a pod that is only slow under load
SLOW_START_PCT = 50  # a pod that takes this share of the time liveness allows it to start is killed if it slows
CORE_DNS_MIN = {True: 3, False: 2}  # CoreDNS replicas, each on its own node, in production and outside it
MIN_REPLICAS = 3  # replicas a production workload runs at its quietest: fewer is the owning team's call to accept
QUOTA_TIGHT = 0.7  # growth that takes this share of the vCPU quota left is worth a look


def _cluster_rows(cluster: dict, a: OutageAnswers) -> list[dict]:
    """What the cluster could grow into at the peak: its node groups' and Karpenter's nodes against the vCPU quota
    left, Karpenter's NodePools against their limits, and KEDA scalers that will not scale."""
    name, region, m = cluster["name"], cluster["region"], a.peak_multiplier
    rows = []
    for q in cluster.get("nodegroup_quota") or []:
        extra = round(q["vcpus"] * (m - 1))
        free = max(q["value"] - q["used"], 0)
        if extra <= QUOTA_TIGHT * free:
            continue
        kind = "spot" if q["spot"] else "on-demand"
        rows.append({"rule": "eks_nodegroup_quota", "res": f"{name}/{q['res']}", "region": region,
                     "sev": "high" if extra > free else "medium",
                     "note": f"{q['what']} at {m:g}x needs {extra:,} more vCPU; {free:,.0f} of the {kind} quota's "
                     f"{q['value']:,.0f} free ({q['code']}), shared with everything else in the region; ask for "
                     f"{q['used'] + extra:,.0f}"})  # fmt: skip
    for p in cluster.get("nodepools") or []:
        cpu = p["res"] == "cpu"
        used, limit = (p["used"] / 1000, p["limit"] / 1000) if cpu else (p["used"] / 1024, p["limit"] / 1024)
        rows.append({"rule": "eks_nodepool_limit", "res": f"{name}/{p['pool']} {p['res']}", "region": region,
                     "pct": 100.0 * p["used"] / p["limit"], "used": round(used, 1), "limit": round(limit, 1),
                     "unit": "vCPU" if cpu else "GiB", "load": True})  # fmt: skip
    for k in cluster.get("keda") or []:
        ready = any(s.startswith("not ready") for s in k["issues"])
        rows.append({"rule": "eks_keda", "res": f"{name}/{k['ns']}/{k['name']}", "region": region,
                     "sev": "high" if ready else "medium",
                     "note": f"ScaledObject {k['so']}: " + "; ".join(k["issues"])})  # fmt: skip
    return rows


def _pending_note(pods: list[dict]) -> str:
    """The most common reasons pods are Pending, with one pod for each."""
    by: dict[str, list[dict]] = {}
    for p in pods:
        by.setdefault(re.sub(r"\d+", "N", p["why"]), []).append(p)
    top = sorted(by.values(), key=lambda x: -len(x))[:3]
    return "; ".join(f"{len(x)} x {x[0]['why']} (e.g. {x[0]['ns']}/{x[0]['pod']})" for x in top)


def _replica_floor(w: dict) -> int | None:
    """The replicas a workload runs at its quietest: its pod autoscaler's minimum, or its fixed count.
    None for an autoscaled workload from a scan older than the read of the minimum."""
    return w.get("hpa_min") if w.get("hpa_max") else w["replicas"]


def workload_rows(cluster: dict, a: OutageAnswers) -> list[dict]:
    """A cluster's Kubernetes workloads as rows, by the floors answered in the report. Workloads in platform
    namespaces are left to the platform team; the cluster-wide checks (CoreDNS among them) still run."""
    name = cluster["name"]
    region = cluster["region"]
    platform = _patterns(a.platform_namespaces)
    rows: list[dict] = []
    add = lambda rule, w, note="", **kw: rows.append(  # noqa: E731
        {"rule": rule, "res": f"{name}/{w['ns']}/{w['name']}", "region": region, "note": note, **kw}
    )
    registries: dict[str, list[dict]] = {}  # images from outside ECR, by registry
    always: list[dict] = []  # ... pulled again on every pod start
    for w in cluster.get("workloads") or []:
        n = w["replicas"]
        if w["name"] == "coredns" and w["ns"] == "kube-system":
            # every lookup in the cluster goes through it: replicas on separate nodes survive a node lost mid-rollout
            spread = w.get("on_nodes", w.get("pods_placed"))  # older scans: only where nodes were read
            low = min(n, spread if spread is not None else n)
            how = f"{n} replica(s)" if spread is None or spread >= n else f"{n} replicas on {spread} node(s)"
            if low < CORE_DNS_MIN[True]:  # under production's bar; outside production only under its own
                add("eks_coredns", w, f"{how}: production needs {CORE_DNS_MIN[True]}, elsewhere "
                    f"{CORE_DNS_MIN[False]}, each on its own node", prod_only=low >= CORE_DNS_MIN[False])  # fmt: skip
        if is_platform(w["ns"], platform):
            continue  # the platform team's: shared with them, not repeated in every account
        if w.get("hpa_max"):
            now = w.get("current", n)
            high = max(now, w.get("hpa_peak") or 0)  # Prometheus's highest over the window, where it was read
            add(
                "eks_hpa_max",
                w,
                f"highest {high} in {cluster.get('prom_days', 0):g} days (Prometheus), {now} now" if high > now else "",
                pct=100.0 * high / w["hpa_max"],
                used=high,
                limit=w["hpa_max"],
                load=True,
            )
            if w.get("hpa_blind"):
                add("eks_hpa_blind", w, f"pod autoscaler {w['hpa']}: {w['hpa_blind']}")
            target, cpu_req, cpu_lim = w.get("hpa_cpu_pct"), w.get("cpu_req"), w.get("cpu_lim")
            if target and cpu_req and cpu_lim and target * cpu_req / cpu_lim >= HPA_LATE_PCT:
                add("eks_hpa_late", w, f"scales at {target}% of a {cpu_req}m request, which is "
                    f"{target * cpu_req / cpu_lim:.0f}% of its {cpu_lim}m limit")  # fmt: skip
        elif w["kind"] == "Deployment" and n >= MIN_REPLICAS:
            add("eks_fixed_replicas", w, f"{n} replicas, no pod autoscaler")
        floor = _replica_floor(w)
        if floor is not None and floor < MIN_REPLICAS:
            add("eks_single_replica", w, f"pod autoscaler {w.get('hpa')} minimum {floor}, so {floor} at quiet times"
                if w.get("hpa_max") else f"{n} {'replica' if n == 1 else 'replicas'}, no pod autoscaler")  # fmt: skip
        if n > 1 and w.get("pods_placed", 0) > 1 and len(w.get("zones") or []) == 1 and cluster.get("zones", 0) > 1:
            add("eks_one_zone", w, f"all {w['pods_placed']} running pods in {w['zones'][0]}; the cluster's nodes "
                f"are in {cluster['zones']} zones")  # fmt: skip
        if n > 1 and len(w.get("vol_zones") or []) == 1:
            add("eks_volume_one_zone", w, f"{n} replicas, every EBS volume in {w['vol_zones'][0]}")
        cpu, mem_lim, mem_req = w.get("cpu_req"), w.get("mem_lim"), w.get("mem_req")
        if cpu is not None and cpu < a.cpu_request_floor_m:
            add("eks_low_cpu", w, f"{cpu}m requested across the pod, under {a.cpu_request_floor_m}m")
        if mem_lim is not None and mem_lim < a.memory_limit_floor_mi:
            add("eks_low_memory", w, f"{mem_lim} MiB limit across the pod, under {a.memory_limit_floor_mi} MiB")
        if mem_lim is None and mem_req is None:
            add("eks_no_memory_limit", w, "no request or limit on at least one container")
        if w.get("pdb") is False and n > 1:
            add("eks_no_pdb", w, f"{n} replicas")
        if w.get("ready") is False:
            add("eks_no_readiness", w, "no container has one")
        if w.get("live") is False:
            add("eks_no_liveness", w, "no container has one")
        live = [p for p in w.get("liveness") or [] if p["app"]]  # a TCP connect does not slow with the app
        if same := next((p for p in live if p["same"]), None):
            add("eks_liveness_same", w, f"container {same['container']}: liveness runs the readiness check")
        if tight := next((p for p in live if p["timeout"] < LIVENESS_TIMEOUT_MIN or p["fails"] == 1), None):
            add("eks_liveness_tight", w, f"container {tight['container']}: restarted after {tight['fails']} "
                f"check(s) of {tight['timeout']}s, {tight['period']}s apart")  # fmt: skip
        start = w.get("to_ready_s")
        for p in w.get("liveness") or []:
            allows = p["delay"] + p["period"] * p["fails"]  # about when liveness kills a container still starting
            if start is not None and not p["startup"] and start >= SLOW_START_PCT / 100 * allows:
                add("eks_slow_start", w, f"quickest pod turned ready {start}s after starting; liveness on container "
                    f"{p['container']} restarts it after about {allows}s, with no startup probe")  # fmt: skip
                break
        if w.get("oom"):
            add("eks_oom", w, f"{w['oom']} container(s) last ended OOMKilled")
        days = cluster.get("prom_days", 0)
        thr = w.get("throttled")
        if thr and thr["pct"] >= THROTTLED_PCT:
            top = max(w.get("current", n), w.get("hpa_peak") or 0)
            at_max = bool(w.get("hpa_max")) and top >= w["hpa_max"]
            sev = "high" if at_max or thr["pct"] >= THROTTLED_HIGH_PCT else "medium"
            note = f"container {thr['container']} throttled in {thr['pct']:g}% of its CPU periods over {days:g} days"
            if at_max:
                note += f", at its pod autoscaler's maximum of {w['hpa_max']} replicas: more pods cannot relieve it"
            peak, limit = thr.get("max_m"), thr.get("limit_m")
            if peak is not None and limit and peak < BURST_PCT / 100 * limit:
                add("eks_cpu_bursts", w, f"{note}; its highest 5-minute CPU was {peak}m of its {limit}m limit",
                    sev=sev)  # fmt: skip
            else:
                add("eks_cpu_throttled", w, note, sev=sev)
        mem = w.get("mem_peak")
        if mem and not cluster.get("insights"):  # Container Insights already gives this, per pod
            add("eks_memory_pressure", w, f"container {mem['container']}, highest in {days:g} days (Prometheus)",
                pct=mem["pct"], used=mem["mib"], limit=mem["limit"], unit="MiB", load=True)  # fmt: skip
        if (w.get("restarts") or 0) >= RESTARTS_FLAG:
            add("eks_restarts", w, f"{w['restarts']} container restarts in {days:g} days (Prometheus)")
        if w.get("pull_failed"):
            add("image_pull_failing", w, f"{w['pull_failed']} container(s) waiting on an image pull that failed")
        for host in w.get("registries") or []:
            registries.setdefault(host, []).append(w)
        if w.get("pull_always"):
            always.append(w)
    for host, found in sorted(registries.items(), key=lambda x: -len(x[1])):
        shown = ", ".join(f"{w['ns']}/{w['name']}" for w in found[:5]) + (
            f" and {len(found) - 5:,} more" if len(found) > 5 else ""
        )
        rows.append({"rule": "image_registry_outside", "res": f"{name} from {host}", "region": region,
                     "used": len(found), "unit": "workloads", "note": shown})  # fmt: skip
    if always:
        shown = ", ".join(f"{w['ns']}/{w['name']}" for w in always[:5]) + (
            f" and {len(always) - 5:,} more" if len(always) > 5 else ""
        )
        rows.append({"rule": "image_pull_always", "res": name, "region": region, "used": len(always),
                     "unit": "workloads", "note": shown})  # fmt: skip
    if cluster.get("pending"):
        rows.append(
            {
                "rule": "eks_pending",
                "res": name,
                "region": region,
                "used": cluster["pending"],
                "unit": "pods pending 15 minutes or more" if "pending_pods" in cluster else "pods pending when read",
                "note": _pending_note(cluster.get("pending_pods") or []),
            }
        )
    rows += _cluster_rows(cluster, a)
    if cluster.get("access") != "read":
        rows.append({"rule": "eks_not_read", "res": name, "region": region, "note": cluster.get("detail", "")})
    return rows


def _region_mismatch(rows: list[dict], values: dict[str, dict[str, float]]) -> list[dict]:
    """A quota whose usage in one region is above its value in another: the second could not take the load."""
    out = []
    for r in rows:
        if not r.get("qcode") or r.get("used") is None or r["region"] == "global":
            continue
        for region, value in (values.get(r["qcode"]) or {}).items():
            if region != r["region"] and r["used"] > value:
                out.append(
                    {
                        "rule": "limit_region_mismatch",
                        "res": r["res"],
                        "region": region,
                        "note": f"{r['used']:,.0f} in use in {r['region']}, limit here {value:,.0f}",
                    }
                )
    return out


def _settled_rds_quotas(raw: dict) -> list[dict]:
    """Saved scans' RDS quotas, read before the fix for counts of resources taken as rates: their usage is 12 times
    too high (AWS gives these an hourly period, and five-minute samples were scaled up to it)."""
    rows = list(raw.get("rows") or [])
    if "profiles" in raw:
        return rows
    out = []
    for r in rows:
        if r.get("qcode") and r["res"].startswith("rds: ") and r.get("load") and not r.get("used", 1) % 12:
            r = {**r, "used": r["used"] / 12, "pct": round(r["pct"] / 12, 1), "load": False}
            if r["pct"] < KEEP_PCT:
                continue
        out.append(r)
    return out


# A rate quota AWS gives no period ("Messages Published per Second"): scans before 0.36.1 read it as a level, the
# busiest hour's count of calls against a limit a second, and stored a whole number with no metric beside it.
RATE_QUOTA_NAME = re.compile(r"per (second|minute|hour|day)\b|\bTPS\b|\btransactions per\b", re.I)


_PER_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def _settled_rate_quotas(rows: list[dict]) -> list[dict]:
    """Saved scans' rate quotas read as levels. With no metric beside them (before 0.36.1) the figure says
    nothing and is left out. 0.36.1 read SNS's rate, published as a ResourceCount, as the sum of the busiest hour:
    that becomes the average over that hour, which is lower than the busiest moment but never higher."""
    out = []
    for r in rows:
        name = RATE_QUOTA_NAME.search(r["res"]) if r.get("qcode") and not r.get("unit") else None
        if not name:
            out.append(r)
            continue
        if "metric" not in r:
            if not float(r.get("used") or 0).is_integer():
                out.append(r)
            continue
        if not r.get("read", "").startswith("Sum per 1 hour"):
            out.append(r)
            continue
        per = 3600 / _PER_SECONDS.get((name.group(1) or "second").lower(), 1)
        used = r["used"] / per
        pct = 100.0 * used / r["limit"] if r.get("limit") else None
        if pct is not None and pct < KEEP_PCT:
            continue
        unit = {"second": "a second", "minute": "a minute"}.get((name.group(1) or "second").lower(), "")
        out.append({**r, "used": round(used, 2), "pct": round(pct, 1) if pct is not None else None, "unit": unit,
                    "read": "Sum per 1 hour, the busiest in 14 days, as an average over that hour"})  # fmt: skip
    return out


def _one_per_quota(rows: list[dict]) -> list[dict]:
    """RDS reports its limits itself and through Service Quotas, by different names: keep one of each."""
    norm = lambda name: re.sub(r"[^a-z]", "", name.lower())  # noqa: E731
    named = {(r["region"], norm(r["res"])) for r in rows if r.get("qcode") and r["res"].startswith("rds: ")}
    return [
        r
        for r in rows
        if r.get("qcode") or not r["res"].startswith("rds: ") or (r["region"], norm(r["res"])) not in named
    ]


# A resource named for a non-production stage, in a production account: judged as non-production.
NONPROD_RESOURCE = re.compile(r"(?<![a-z0-9])(dev|qa|uat|sit|test|poc|sandbox|sbx)(?![a-z0-9])", re.I)
QUOTA_RULES = {"limit_product", "limit_account", "limit_connect"}
QUOTA_OVER = 110.0  # AWS enforces a quota: usage well past it means the figure is not that quota's usage
DLQ = re.compile(r"dlq|dead[-_ ]?letter|(?<![a-z0-9])dl(?![a-z0-9])", re.I)
SHORT_RETENTION = re.compile(
    r"deleted after 0 hours"
)  # a queue that keeps messages under an hour drops them on purpose
# A queue that holds messages rejected as invalid or failed, kept for a person to look at: like a dead-letter queue
SINK_QUEUE = re.compile(r"(?<![a-z0-9])(invalid|errors?|rejects?|rejected|failed)(?![a-z0-9])", re.I)
READ_API = re.compile(r"\b(Describe|List|Get|Search)[A-Z]\w*|describe .* information rate", re.I)
NO_FREEABLE = ("oracle", "sqlserver", "db2")  # these engines allocate their memory up front
BUFFER_POOL = ("aurora", "mysql", "mariadb")  # these give about 3/4 of memory to their cache at start
BUFFER_SHARE = 0.25  # the share of memory left for connections, sorts and the operating system


def _stat(profile: dict | None, key: str) -> dict:
    return next((s for s in (profile or {}).get("stats") or [] if s.get("k") == key), {})


def _false_positive(row: dict, profiles: dict) -> bool:
    """A reading that cannot be what it claims. profiles: {(svc, res): the resource's review}."""
    facts = {k: p.get("facts") or {} for k, p in profiles.items()}
    rule, pct = row["rule"], row.get("pct") or 0.0
    if rule in QUOTA_RULES and pct > QUOTA_OVER:
        return True  # an enforced limit exceeded: a raised quota the API does not show, or a mismatched metric
    if rule in ("ebs_iops_use", "rds_iops") and pct > QUOTA_OVER:
        return True  # past what is provisioned: the busiest read and write hours do not add up
    if rule == "sqs_backlog" and (DLQ.search(row["res"]) or SHORT_RETENTION.search(row.get("note", ""))):
        return True  # a dead-letter queue holds messages on purpose; a short retention drops stale ones by design
    if rule == "efs_burst":
        f = facts.get(("efs", row["res"])) or {}
        if f.get("Throughput") not in (None, "bursting") or str(f.get("Size", "")).startswith("0.0 "):
            return True  # credits only matter in bursting mode, and an empty file system never earns any
    if rule == "rds_memory":
        engine = str((facts.get(("rds", row["res"])) or {}).get("Engine") or row.get("engine") or "")
        if engine.startswith(NO_FREEABLE):
            return True
    if rule == "no_alarm" and row["res"].startswith("rds: "):
        engine = str((facts.get(("rds", row["res"][5:])) or {}).get("Engine") or "")
        if engine.startswith(("aurora", "docdb", "neptune")):
            return True  # cluster storage grows by itself and has no FreeStorageSpace to alarm on
    return False


SERVERLESS_MAX_ACU = 256  # the most Aurora Serverless v2 allows, on current engine versions
SERVERLESS_NOTE = (
    "AWS measures Aurora Serverless v2 CPU against the maximum ACUs, so CPU is the headroom left before the "
    "ceiling. Capacity used is held up by the buffer cache and falls slowly, so it does not grow with load"
)


def acu_advice(row: dict, a: OutageAnswers) -> str:
    """What the minimum and maximum ACUs are, and what to set the maximum to: the busiest hour's CPU,
    in ACUs, at the expected peak load, with the warning level's headroom left over."""
    top, low, cpu = row.get("acu_max"), row.get("acu_min"), row.get("cpu_acus")
    if not top:
        return ""
    said = [f"now {low:g} to {top:g} ACUs"]
    if row.get("changed"):
        was = row["changed"]
        said.append(
            f"the maximum was {was['was']:g} until {was['until']}, "
            f"so earlier peaks are measured against today's {top:g}"
        )
    if cpu is None or row["rule"] != "aurora_acu":
        return "; ".join(said)
    need = cpu * a.peak_multiplier
    want = need / (a.warn_pct / 100)
    step = 8 if want > 16 else 1
    rec = math.ceil(want / step) * step
    said.append(f"the busiest hour used {cpu:g} ACUs of CPU, about {need:.0f} at {a.peak_multiplier:g}x load")
    if rec <= top:
        said.append("today's maximum covers that")
    elif rec <= SERVERLESS_MAX_ACU:
        said.append(
            f"raise the maximum to {rec:g} ACUs, which leaves {100 - a.warn_pct}% headroom at the peak; "
            "the minimum does not limit the peak and can stay"
        )
    else:
        said.append(
            f"that needs about {rec:g} ACUs, past the {SERVERLESS_MAX_ACU} Aurora Serverless v2 allows: "
            f"set the maximum to {SERVERLESS_MAX_ACU} and move reads to a reader endpoint, "
            "or move the writer to a provisioned class"
        )
    return "; ".join(said)


def _rebase(row: dict, profiles: dict) -> dict:
    """A measure judged against the headroom the engine really has. MySQL, MariaDB and Aurora give about
    three quarters of memory to the buffer pool or cache when they start, by design: low freeable memory
    there is normal, so it is measured against the remaining quarter."""
    if row["rule"] == "aurora_acu" and row.get("cpu_acus") is not None:
        return row  # already CPU against today's maximum ACUs: see acu_advice
    if row["rule"] == "aurora_acu" and row.get("pct") is not None:
        cpu = _stat(profiles.get(("rds", row["res"])), "CPU")
        if cpu.get("peak") is None:
            return {**row, "evidence": "thin"}
        used = f"capacity used {row['pct']:.0f}% of the maximum ACUs"
        note = f"{used}, CPU {cpu['peak']:.0f}% of the maximum at the busiest hour. {SERVERLESS_NOTE}"
        return {**row, "pct": round(min(cpu["peak"], 100.0), 1), "note": note, "acu_used": row["pct"]}
    if row["rule"] != "rds_memory" or row.get("pct") is None:
        return row
    engine = str(((profiles.get(("rds", row["res"])) or {}).get("facts") or {}).get("Engine") or "")
    if not engine.startswith(BUFFER_POOL):
        return row
    pct = max(0.0, 100.0 - (100.0 - row["pct"]) / BUFFER_SHARE)
    cache = f"{engine.split()[0]} keeps about three quarters of memory as cache by design, so measured against the rest"
    note = f"{row.get('note', '')}; {cache}"
    return {**row, "pct": round(pct, 1), "note": note.lstrip("; ")}


# Events seen in the lookback window count as an outage sign only when they are a real share of the
# traffic: a handful of errors in 35 days is noise every busy system has.
ERROR_SHARE = 0.01  # of requests, on average
MIN_EVENTS = 100  # in the lookback window
NAT_DROPS = 10_000  # packets in the lookback window; a few dropped packets are retransmitted unnoticed
SQS_BACKLOG = 100  # messages waiting: below it, an old message is a few left unconsumed, not a stalled consumer
# Rated against these traffic figures: {rule: (svc, [(failures, requests)])}
EVENT_RATES = {
    "apigw_5xx": ("apigateway", [("Server errors", "Requests")]),
    "lb_5xx": ("elb", [("Own 5xx errors", "Requests")]),
    "lambda_throttles": ("lambda", [("Throttles", "Invocations")]),
    "lambda_async_dropped": ("lambda", [("Errors", "Invocations")]),
    "ddb_throttles": ("dynamodb", [("Read throttles", "Reads"), ("Write throttles", "Writes")]),
}
# A count of things created, not traffic: at the quota nothing new can be added, but what runs is not hit.
STATIC_QUOTA = re.compile(
    r"phone numbers|queues|flows|users|routing profiles|hours of operation|security profiles|prompts|"
    r"domains|tracking server|serverless endpoints|apps running|notebook|spaces|user profiles",
    re.I,
)
# Amazon Connect API rates. The calls that set up users, queues and hierarchies come from admin or sync tooling;
# the rest follow the contact centre's staff, which is fixed, so the peak multiplier does not apply to them.
CONNECT_RATE = re.compile(r"^connect: Rate of (\w+) API", re.I)
ADMIN_API = re.compile(
    r"^(Update|Create|Delete|Associate|Disassociate|Put|Tag|Untag|Batch|Import|Replicate|Claim|Release)"
)
ANALYST_QUOTA = re.compile(r"^(sagemaker|athena|glue|quicksight|databrew|emr-serverless|bedrock): ", re.I)
# Build, CI and housekeeping tooling: when it stops, delivery waits, but customers are not hit.
TOOLING = re.compile(
    r"github-?runner|gitlab-?runner|(?<![a-z0-9])runners?(?![a-z0-9])|jenkins|sonarqube|buildkite|atlantis|"
    r"image-?builder|idle-?reaper|warm-?pool|security-?hub|(?<![a-z0-9])backup-test(?![a-z0-9])|"
    r"(?<![a-z0-9])restore(?![a-z])",
    re.I,
)


LOOKBACK_HOURS = 35 * 24
LAMBDA_RULES = {"lambda_timeout", "lambda_async_dropped", "lambda_throttles", "lambda_reserved", "lambda_pc_util"}
JOB_AVG = 0.005  # calls a second on average (under one every three minutes), and
JOB_PEAK = 0.05  # at the busiest hour (under three a minute): a scheduled or triggered job, not a request path


def _share(prof: dict | None, pairs) -> float | None:
    """The worst share of requests that failed, on average across the window (None: traffic not read).
    Refused calls are not counted in the traffic figure, so they are added to it."""
    shares = []
    for bad, total in pairs:
        b, t = _stat(prof, bad), _stat(prof, total)
        if b and t:
            failed, served = b.get("avg") or 0, (t.get("avg") or 0) * 3600  # failures an hour, requests a second
            if failed + served > 0:
                shares.append(failed / (failed + served))
    return max(shares) if shares else None


def _rare(prof: dict | None, bad: str, total: str) -> str | None:
    """Why a failure count beside a resource is too rare to be an outage sign, or None when it is not."""
    b = _stat(prof, bad)
    count = (b.get("avg") or 0) * LOOKBACK_HOURS
    share = _share(prof, [(bad, total)]) or 0.0
    if count < MIN_EVENTS or share < ERROR_SHARE:
        return f"about {count:,.0f} {bad.lower()} in 35 days, {share:.2%} of calls: too rare to be an outage sign"
    return None


def _lower_to(f: dict, severity: str, why: str) -> None:
    f["severity"] = severity
    f["why"] += f"; {why}"


# Faults read over the lookback that are measured again for the last hour: once recovered they are history,
# not an issue (a broker restart, a deployment, an incident already fixed).
RECOVERS = {"msk_offline", "msk_under_replicated", "lb_no_healthy"}


def _since_fixed(f: dict, row: dict) -> None:
    """A fault in the lookback window, judged by when it last happened (rows from the collector's fault_fields).
    Capacity changed after it last happened, and not failed since: fixed, so left out of the actions and listed
    as fixed. Every hour of it close to an upgrade or a configuration change being applied: it came with that
    change (an OpenSearch blue/green deployment shows red while shards move), not from load, so low."""
    if not row.get("last"):
        return
    f["last"] = row["last"]
    if row.get("changed"):
        f["recovered"] = True
        f["fixed"] = f"{row['change']} on {row['changed'][:10]}, after it last failed on {row['last'][:10]}"
    elif row.get("during"):
        f["severity"] = "low"
        what, _, when = row["during"].partition(" on ")
        f["why"] += f"; only while {what} was being applied on {when[:10]}, not since: make changes outside busy hours"
    else:
        f["why"] += f"; last on {row['last'][:10]}"


def _temper(f: dict, row: dict, profiles: dict) -> None:
    """Lower a finding the evidence beside it does not bear out, and say why. Critical and high are kept
    for what is likely to cause an outage at the peak; the rest stays listed, lower, with the reason."""
    if f["severity"] not in ("critical", "high"):
        return
    rule = row["rule"]
    res = row["res"]
    calls = _stat(profiles.get(("lambda", res)), "Invocations") if rule in LAMBDA_RULES else {}
    if calls and (calls.get("avg") or 0) < JOB_AVG and (calls.get("peak") or 0) < JOB_PEAK:
        _lower_to(
            f,
            "medium",
            "a background job (almost never called): it fails its own work, not customer traffic at the peak",
        )
    elif row.get("evidence") == "thin":
        _lower_to(
            f,
            "medium",
            "insufficient evidence: CPU was not read, and capacity used alone does not show the ceiling is near",
        )
    elif rule in QUOTA_RULES and CONNECT_RATE.search(res) and ADMIN_API.match(CONNECT_RATE.search(res).group(1)):
        _lower_to(f, "medium", "an admin API called by setup or sync tooling that retries, not by agents or customers")
    elif rule in QUOTA_RULES and CONNECT_RATE.search(res) and not READ_API.search(res):
        f["at_peak"] = f["pct"]  # staff-bound: the busiest day is about as busy as today
        if (f["pct"] or 0) >= 100:
            _lower_to(
                f,
                "high",
                "judged on today, not at 2x: the contact centre's staff is fixed; past the rate, calls are refused",
            )
        else:
            _lower_to(f, "medium", "judged on today, not at 2x: the contact centre's staff is fixed, so volume is too")
    elif rule in QUOTA_RULES and READ_API.search(res) and row.get("load"):
        _lower_to(f, "medium", "a read API, usually called by tooling that retries, not by customers")
    elif rule in QUOTA_RULES and ANALYST_QUOTA.search(res):
        _lower_to(
            f, "medium", "an analyst or data science service: at the quota work queues or waits, customers are not hit"
        )
    elif rule in QUOTA_RULES and STATIC_QUOTA.search(res) and not row.get("load"):
        _lower_to(
            f, "medium", "a count of things created: at the quota nothing new can be added, what runs keeps working"
        )
    elif rule in EVENT_RATES:
        svc, pairs = EVENT_RATES[rule]
        share = _share(profiles.get((svc, res)), pairs)
        total = row.get("used") or 0
        if share is None:
            _lower_to(
                f, "medium", "insufficient evidence: the traffic beside it was not read, so its share is not known"
            )
        elif total < MIN_EVENTS or share < ERROR_SHARE:
            sev = "medium" if total >= MIN_EVENTS else "low"
            _lower_to(f, sev, f"about {share:.2%} of requests on average: background noise, not a sign of an outage")
        else:
            f["why"] += f"; about {share:.1%} of requests on average"
    elif rule == "nat_drops" and (row.get("used") or 0) < NAT_DROPS:
        sev = "medium" if (row.get("used") or 0) >= MIN_EVENTS else "low"
        _lower_to(f, sev, "a few packets in 35 days: TCP sends them again, so nothing fails")
    elif rule in RECOVERS and not row.get("now") and ("now" in row or rule != "msk_offline"):  # older scans: no now
        f["recovered"] = True  # a past fault that has since been fixed: not an issue to report
    elif rule in ("lambda_reserved", "lambda_pc_util"):
        prof = profiles.get(("lambda", res))
        rare = _rare(prof, "Throttles", "Invocations")
        if rare:
            past = "calls past it run on demand with a cold start, they do not fail" if rule == "lambda_pc_util" else ""
            _lower_to(f, "medium", f"{rare}{'; ' + past if past else ''}")
    elif rule == "lambda_timeout":
        prof = profiles.get(("lambda", res))
        errors = _stat(prof, "Errors").get("peak") or 0
        if (row.get("pct") or 0) > 101 and not errors:
            f["severity"] = "medium"
            f["why"] = (
                "its longest run is longer than today's timeout, so the timeout was lowered in the window; "
                "no errors since"
            )
        elif not errors:
            _lower_to(f, "medium", "no errors recorded, so no run was cut off yet")
        elif rare := _rare(prof, "Errors", "Invocations"):
            _lower_to(f, "medium", rare)
    elif rule == "sqs_backlog" and SINK_QUEUE.search(res.replace("_", "-")):
        _lower_to(f, "medium", "a queue of invalid or failed messages, kept to be looked at: check why they fail")
    elif rule == "sqs_backlog" and row.get("received") == 0:
        sent = row.get("sent") or 0
        if sent:
            _lower_to(
                f,
                "medium",
                f"nobody reads this queue: {sent:,} messages sent in the window and none received, so each expires "
                "unread. Not an outage risk at the peak, it is already so: check whether anything should read it "
                "(if so, data is being lost now) or remove what sends to it",
            )
        else:
            _lower_to(f, "low", "an idle queue: nothing sent or read in the window, so its old messages expire")
    elif rule == "sqs_backlog" and row.get("received") and (row.get("age_now_pct") or 0) < 50:
        _lower_to(
            f,
            "medium",
            f"its consumers read it and have caught up (oldest message now {row['age_now_pct']:.0f}% of its expiry); "
            "it reached its expiry at the busiest time in the window, so check the consumers scale for the peak",
        )
    elif rule == "sqs_backlog":
        waiting = _stat(profiles.get(("sqs", res)), "Messages waiting").get("peak") or 0
        if waiting < SQS_BACKLOG:
            _lower_to(
                f,
                "medium",
                f"at most {waiting:,.0f} messages waiting: a few left unconsumed expire, the queue is not stalled",
            )
    elif rule in ("redshift_cpu", "ebs_iops_use") and f["severity"] == "high" and row.get("load"):
        what = (
            "a data warehouse: at its limit queries queue and reports run late, customers are not hit"
            if rule == "redshift_cpu"
            else "a projection of an hourly average: busy hours on a volume are usually backups or batch jobs"
        )
        _lower_to(f, "medium", what)
    elif rule == "kinesis_iterator":
        behind = _stat(profiles.get(("kinesis", res)), "Reader behind")
        if behind.get("peak") and (behind.get("avg") or 0) < 0.1 * behind["peak"]:
            f["severity"] = "medium"
            f["why"] = (
                f"a reader started from the oldest record once (a restart or a new consumer) and caught up: "
                f"{behind['avg'] / 60:,.0f} minutes behind on average"
            )


NON_PROD_WEIGHT = 0.1  # a non-production account's weight in the overall score


def _offline_now(rows: list[dict]) -> None:
    """Scans before the last hour was kept for offline partitions: an offline partition is also
    under-replicated, so the cluster's under-replication now (read in the same scan) says whether it recovered."""
    urp = {r["res"]: r["now"] for r in rows if r["rule"] == "msk_under_replicated" and "now" in r}
    for r in rows:
        if r["rule"] == "msk_offline" and "now" not in r and r["res"] in urp:
            r["now"] = urp[r["res"]]


def _accounts_and_findings(
    scan, accounts, checked, rules, a, peak, days_to_peak, taken=None
) -> tuple[list[dict], list[dict], list[dict]]:
    """(account table, findings counted, findings accepted). ``taken`` are the accepted risk rules: a finding one
    covers leaves the scores, the counts and every action list, and is listed apart."""
    taken = taken or []
    points = catalog()["points"]
    prod_p = prod_rule(a)
    spend = _monthly_spend(scan)
    table, findings, accepted = [], [], []
    for acct in accounts:
        raw = checked.get(acct["id"])
        if raw is None:
            continue
        production, prod_by = production_why(acct, prod_p)
        rows = _one_per_quota(_settled_rate_quotas(_settled_rds_quotas(raw)))
        rows += _region_mismatch(rows, raw.get("quota_values") or {})
        for c in raw.get("clusters") or []:
            rows += workload_rows(c, a)
        profiles = {(p["svc"], p["res"]): p for p in raw.get("profiles") or []}
        _offline_now(rows)
        found, fixed = [], []
        for row in rows:
            rule = rules.get(row["rule"])
            if not rule or _false_positive(row, profiles):
                continue
            named = f"{row['res']} {row.get('note', '')}"
            live = production and not NONPROD_RESOURCE.search(named) and not TOOLING.search(named)
            based = _rebase(row, profiles)
            f = _judge(based, rule, a, peak, days_to_peak, live)
            if f:
                if based.get("acu_used") is not None:
                    f["why"] = f"CPU {f['why']}; capacity used {based['acu_used']:.0f}% of the maximum ACUs"
                advice = acu_advice(based, a) if rule["id"] in ("aurora_acu", "aurora_acu_ceiling") else ""
                if advice:
                    f["why"] = f"{f['why']}; {advice}"
                    f["advice"] = advice
                _since_fixed(f, based)
                _temper(f, based, profiles)
                if f.get("fixed"):
                    fixed.append({k: f.get(k) for k in ("rule", "res", "region", "fixed", "last")} | {
                        "title": rule["title"], "service": rule.get("area", "")})  # fmt: skip
                if f.get("recovered"):
                    continue
                found.append(
                    {
                        **f,
                        "account": acct["name"],
                        "account_id": acct["id"],
                        "production": live,
                        "area": rule["area"],
                        "title": rule["title"],
                        **({"tags": row["tags"]} if row.get("tags") else {}),
                    }
                )
        found, mine_accepted = accepted_risks.judge(found, taken)
        accepted += mine_accepted
        worst: dict[str, str] = {}
        for f in found:
            if f["rule"] not in worst or SEV_ORDER[f["severity"]] < SEV_ORDER[worst[f["rule"]]]:
                worst[f["rule"]] = f["severity"]
        score = round(_points_score(list(worst.values()), points, 1.0), 1) if worst else 0.0
        counts = Counter(f["severity"] for f in found)
        top = min(found, key=lambda f: (SEV_ORDER[f["severity"]], -(f["at_peak"] or 0)), default=None)
        checks = raw.get("checks") or {}
        # A check that passed in one region and failed to read in another is not measured either.
        unread = [
            k for k, v in checks.items() if v.get("status") == "unknown" or "not measured" in (v.get("note") or "")
        ]
        unread_why = unread_kinds({k: checks[k] for k in unread})
        disks = disk_sight(raw.get("facts") or {})
        blind = bool(checks) and not any(v.get("status") in ("pass", "fail") for v in checks.values())
        blind = blind and not found and any(v.get("status") == "unknown" for v in checks.values())
        table.append(
            {
                "id": acct["id"],
                "name": acct["name"],
                "ou_path": acct.get("ou_path", ""),
                "owner": owner_of(acct)[0],
                "production": production,
                "production_by": prod_by,
                "score": score,
                "rating": NOT_MEASURED if blind else _rating(score),
                "monthly_spend": spend.get(acct["id"], 0.0),
                **{s: counts.get(s, 0) for s in SEVERITIES},
                "top": f"{top['title']}: {top['res']}" if top else "",
                "not_measured": unread,
                "not_measured_why": unread_why,
                "regions": raw.get("regions") or [],
                "compared": raw.get("compared", 0),
                "rows_cut": raw.get("rows_cut", 0),
                "metrics_cut": bool((raw.get("facts") or {}).get("metrics_cut")),
                "disks": disks,
                "fixed": fixed,  # faults in the lookback with capacity changed after them: not actions
                "accepted": len(mine_accepted),
            }
        )
        findings += found
    table.sort(
        key=lambda r: (
            r["rating"] != NOT_MEASURED,
            -r["score"],
            not r["production"],
            -r["critical"],
            -r["high"],
            r["name"].lower(),
        )
    )
    findings.sort(
        key=lambda f: (not f["production"], SEV_ORDER[f["severity"]], -(f["at_peak"] or f["pct"] or 0), f["account"])
    )
    accepted.sort(key=lambda f: (f["account"], SEV_ORDER[f["severity"]], f["res"]))
    return table, findings, accepted


def _focus(findings: list[dict], cat: dict, peak: date, freeze: date, today: date) -> list[dict]:
    """The areas, in the order the scan's production findings say to work on them."""
    out = []
    for area, info in cat["areas"].items():
        mine = [f for f in findings if f["area"] == area and f["production"]]
        counts = Counter(f["severity"] for f in mine)
        rules = Counter(f["title"] for f in mine if f["severity"] in ("critical", "high"))
        start = min(freeze, peak) - timedelta(days=info.get("lead_days", 0))
        out.append(
            {
                "area": area,
                "label": info["label"],
                "action": info["action"],
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "accounts": len({f["account_id"] for f in mine}),
                "top": [{"title": t, "count": n} for t, n in rules.most_common(3)],
                "start_by": start.isoformat(),
                "late": start < today,
            }
        )
    out.sort(key=lambda x: (-x["critical"], -x["high"], -x["medium"], x["label"]))
    return out


def _rule_rollup(findings: list[dict], rules: dict) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        grouped[f["rule"]].append(f)
    out = []
    for rid, mine in grouped.items():
        rule = rules[rid]
        counts = Counter(f["severity"] for f in mine)
        out.append(
            {
                "id": rid,
                "title": rule["title"],
                "area": rule["area"],
                "kind": rule["kind"],
                "why": rule["why"],
                "fix": rule["fix"],
                "findings": len(mine),
                "accounts": len({f["account_id"] for f in mine}),
                "production": sum(f["production"] for f in mine),
                **{s: counts.get(s, 0) for s in SEVERITIES},
            }
        )
    out.sort(key=lambda r: (-r["critical"], -r["high"], -r["findings"]))
    return out


def _node_view(c: dict) -> dict:
    """What a cluster's nodes show, when the scan could read them: requests against what the nodes can hold
    (left out when the pods were read only up to the limit, as the sum would be short)."""
    if c.get("access") != "read":
        return {}
    if c.get("node_access") != "read":
        return {"node_access": c.get("node_access") or "not read"}
    pct = (
        None
        if c.get("pods_cut")
        else {k: round(100 * c[f"req_{k}"] / c[f"alloc_{k}"]) if c.get(f"alloc_{k}") else None for k in ("cpu", "mem")}
    )
    return {
        "node_access": "read",
        "nodes": c.get("nodes"),
        "not_ready": c.get("not_ready") or [],
        "pressure": c.get("pressure") or {},
        "requested_pct": pct,
    }


def _clusters(accounts: list[dict], checked: dict, a: OutageAnswers) -> list[dict]:
    platform = _patterns(a.platform_namespaces)
    out = []
    for acct in accounts:
        for c in (checked.get(acct["id"]) or {}).get("clusters") or []:
            ws = c.get("workloads") or []
            out.append(
                {
                    "account": acct["name"],
                    "name": c["name"],
                    "region": c["region"],
                    "version": c.get("version", ""),
                    "access": c.get("access"),
                    "detail": c.get("detail", ""),
                    "principal": c.get("principal", ""),
                    "insights": bool(c.get("insights")),
                    "pods": c.get("pods"),
                    "workloads": c.get("workload_count", len(ws)),
                    "autoscaled": sum(1 for w in ws if w.get("hpa_max")),
                    "few": sum(1 for w in ws if (_replica_floor(w) or MIN_REPLICAS) < MIN_REPLICAS),
                    "pods_cut": bool(c.get("pods_cut")),
                    "karpenter": c.get("karpenter"),
                    "prom_access": c.get("prom_access", ""),
                    "prometheus": c.get("prometheus", ""),
                    "prom_days": c.get("prom_days"),
                    "volume_access": c.get("volume_access", ""),
                    "keda_access": c.get("keda_access", ""),
                    "nodepool_access": c.get("nodepool_access", ""),
                    # the platform team's namespaces seen in the cluster: its workloads there are shared with them
                    "platform_ns": sorted({w["ns"] for w in ws if is_platform(w["ns"], platform)}),
                    **_node_view(c),
                }
            )
    out.sort(key=lambda c: (c["access"] == "read", c["account"], c["name"]))
    return out


def unread_kinds(checks: dict[str, dict]) -> dict[str, list[str]]:
    """{kind: [check ids]} for checks not measured, by why (issues.failure_kind). A check's note holds
    "<code> in <region>" for each place it failed; a check that failed for two reasons is under both."""
    out: dict[str, list[str]] = {k: [] for k in FAILURE_KINDS}
    for cid, v in checks.items():
        note = (v.get("note") or "").removeprefix("not measured in part: ")
        kinds = set()
        for part in note.split("; "):
            # "<code> in <region>", or for a metric "<metric> in <region> answered <status>"
            code = part.rsplit(" answered ", 1)[1] if " answered " in part else ""
            if not code and " in " in part and " " not in part.split(" in ", 1)[1].strip():
                code = part.split(" in ", 1)[0].strip()
            kinds.add(failure_kind(code) if code else "other")
        for k in sorted(kinds or {"other"}):
            out[k].append(cid)
    return {k: v for k, v in out.items() if v}


def disk_sight(facts: dict) -> dict:
    """Across an account's regions: running servers, those whose disks nobody reports (no CloudWatch agent
    and no df answer), how many of those are not in an Auto Scaling group or EKS, and where df stopped."""
    by_region = facts.get("disks") or {}
    out = {k: sum(int(r.get(k) or 0) for r in by_region.values()) for k in ("running", "seen", "blind", "blind_fixed")}
    out["examples"] = [x for r in by_region.values() for x in r.get("examples") or []][:10]
    out["df_stopped"] = [f"{region}: {s.get('why')}" for region, s in (facts.get("df_stopped") or {}).items()]
    out["df_failed"] = sum(len(v) for v in (facts.get("df_failed") or {}).values())
    return out


def _summary(table, findings, clusters, not_checked, a, peak, freeze, today) -> dict:
    prod = [f for f in findings if f["production"]]
    counts = Counter(f["severity"] for f in prod)
    all_counts = Counter(f["severity"] for f in findings)
    limited = [f for f in prod if f["area"] == "limits"]
    # Production accounts carry the score; spend plays no part, as it is only a proxy for importance.
    weights = [(r["score"], 1.0 if r["production"] else NON_PROD_WEIGHT) for r in table if r["rating"] != NOT_MEASURED]
    total = sum(w for _, w in weights)
    score = round(sum(s * w for s, w in weights) / total, 1) if total else 0.0
    checks = sum(r["compared"] for r in table)
    measured = [r for r in table if not r["not_measured"]]
    why = {k: sum(1 for r in table if (r.get("not_measured_why") or {}).get(k)) for k in FAILURE_KINDS}
    disks = [r.get("disks") or {} for r in table]
    return {
        "accounts": len(table),
        "not_checked": len(not_checked),
        # Servers whose disk use nobody reports: a full disk there is not seen. Absent in scans made before.
        "servers": sum(d.get("running", 0) for d in disks),
        "servers_blind": sum(d.get("blind", 0) for d in disks),
        "servers_blind_fixed": sum(d.get("blind_fixed", 0) for d in disks),
        "servers_read": any("running" in d for d in disks),
        "df_stopped": sum(len(d.get("df_stopped") or []) for d in disks),
        "df_failed": sum(d.get("df_failed", 0) for d in disks),
        "accounts_full": len(measured),
        # Accounts with a check not measured, by why: refused for lack of permission, timed out or throttled
        # (Complete the scan reads them again), or failed for another reason. An account can be in several.
        "accounts_denied": why["permission"],
        "accounts_retry": why["retry"],
        "accounts_other": why["other"],
        "accounts_blind": sum(1 for r in table if r["rating"] == NOT_MEASURED),
        "accounts_cut": sum(1 for r in table if r["rows_cut"] or r["metrics_cut"]),
        "score": score,
        "rating": _rating(score),
        "critical_accounts": sum(1 for r in table if r["rating"] == "Critical"),
        "high_accounts": sum(1 for r in table if r["rating"] == "High"),
        "production_accounts": sum(1 for r in table if r["production"]),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "all_findings": sum(all_counts.values()),
        "non_production": len(findings) - len(prod),
        "breach_at_peak": sum(1 for f in prod if f["kind_capacity"] and (f["at_peak"] or 0) >= 100),
        "limits_at_risk": sum(1 for f in limited if f["severity"] in ("critical", "high")),
        "hard_limits": sum(1 for f in limited if f["hard"] and f["severity"] in ("critical", "high")),
        "full_before_peak": sum(1 for f in prod if f["days"] is not None and f["days"] <= (peak - today).days),
        "hot_fixed": sum(
            1 for f in prod if f["area"] == "fixed" and f["kind_capacity"] and f["severity"] in ("critical", "high")
        ),
        "msk_at_risk": sum(1 for f in prod if f["area"] == "msk" and f["severity"] in ("critical", "high")),
        "eks_fixed": sum(1 for f in prod if f["rule"] == "eks_fixed_replicas"),
        "eks_few": sum(1 for f in prod if f["rule"] == "eks_single_replica"),
        "clusters": len(clusters),
        "clusters_read": sum(1 for c in clusters if c["access"] == "read"),
        "measures": checks,
        "peak_date": peak.isoformat(),
        "days_to_peak": (peak - today).days,
        "freeze_date": freeze.isoformat(),
        "days_to_freeze": (freeze - today).days,
        "multiplier": a.peak_multiplier,
    }


def build_outage(
    scan: dict,
    account_filter: AccountFilter | None = None,
    a: OutageAnswers | None = None,
    taken: list[dict] | None = None,
) -> dict:
    """The outage risk report. ``taken`` are the accepted risk rules; None reads the saved ones."""
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    a = a or OutageAnswers()
    cat = catalog()
    rules = {r["id"]: r for r in cat["rules"]}
    data = scan.get("outage") or {}
    checked = data.get("accounts") or {}
    accounts = [x for x in scan.get("accounts", []) if account_filter.matches(x["name"])]
    today = date.today()
    peak = date.fromisoformat(a.peak_date) if a.peak_date else black_friday(today)
    freeze = peak - timedelta(days=a.freeze_days)
    base = {
        "scan_id": scan.get("id"),
        "label": scan.get("label", ""),
        "scan_at": scan.get("created_at"),
        "ou": scan.get("ou"),
        "answers": a.model_dump(),
        "catalog_version": cat.get("version"),
        "filter": account_filter.describe() if account_filter.active else "",
    }
    if not checked:
        return {**base, "available": False, "accounts": [], "reason": _why_empty(scan)}
    taken = accepted_risks.load() if taken is None else taken
    table, findings, accepted = _accounts_and_findings(
        scan, accounts, checked, rules, a, peak, (peak - today).days, taken
    )
    label_services(accepted)
    lapsed = [f for f in findings if f.get("accepted_lapsed")]
    for f in findings:
        f["kind_capacity"] = rules[f["rule"]]["kind"] == "capacity"
    clusters = _clusters(accounts, checked, a)
    not_checked = [
        {"id": x["id"], "name": x["name"]}
        for x in accounts
        if x["id"] not in checked and x.get("status", "ACTIVE") in ("ACTIVE", "UNKNOWN")
    ]
    focus = _focus(findings, cat, peak, freeze, today)
    views = build_views(scan, accounts, checked, table, findings, rules, cat, peak, freeze, today)
    area_rank = {x["area"]: x for x in focus}

    def found_for(cause: dict) -> dict | None:
        """What this scan found for a cause: its area, or the rules named. None when a scan cannot see it."""
        if cause.get("rules"):
            hits = [f for f in findings if f["rule"] in cause["rules"] and f["production"]]
            return {sev: sum(f["severity"] == sev for f in hits) for sev in ("critical", "high", "medium")}
        return area_rank.get(cause.get("area") or "")

    # The evidence, beside what this scan found for the same cause.
    causes = [{**c, "scan": found_for(c)} for c in cat["causes"]]
    return {
        **base,
        "available": True,
        "summary": _summary(table, findings, clusters, not_checked, a, peak, freeze, today),
        "focus": focus,
        "causes": causes,
        "areas": {k: v["label"] for k, v in cat["areas"].items()},
        "rules": _rule_rollup(findings, rules),
        "findings": findings[:MAX_FINDINGS],
        "findings_total": len(findings),
        "accepted": accepted[:MAX_FINDINGS],
        "accepted_total": len(accepted),
        "accepted_rules": accepted_risks.summary(taken, accepted, lapsed, today),
        "accepted_returned": len(lapsed),
        "accounts": table,
        "clusters": clusters,
        "not_checked": not_checked,
        **views,
        "build_ms": round((time.perf_counter() - started) * 1000),
    }


def _why_empty(scan: dict) -> str:
    if (scan.get("params") or {}).get("outage"):
        return (
            "This scan was asked for the outage risk checks but could not read any account: "
            "see the issues in section 9 of the Exit Risk Report."
        )
    return "This scan did not run the outage risk checks."


def _cell(value):
    """A resource name is the customer's text: a spreadsheet must not run one that looks like a formula."""
    return f"'{value}" if isinstance(value, str) and value[:1] in ("=", "+", "-", "@") else value


def findings_csv(report: dict) -> str:
    """Every finding sent to the page, for a spreadsheet or a ticket system."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(
        [
            "severity",
            "area",
            "service",
            "finding",
            "account",
            "owner",
            "production",
            "region",
            "resource",
            "percent now",
            "percent at peak",
            "used",
            "limit",
            "unit",
            "days to full",
            "why",
            "note",
            "what to do",
            "accepted risk",
        ]
    )
    areas = report.get("areas") or {}
    owners = {a["id"]: a.get("owner") or "" for a in report.get("accounts") or []}
    fixes = {r["id"]: r.get("fix", "") for r in report.get("rules") or []}

    def status(f: dict) -> str:
        if f.get("accepted"):
            x = f["accepted"]
            return f"accepted by {x['accepted_by']} until {x['review_on']}, not counted: {x['reason']}"
        if f.get("accepted_lapsed"):
            x = f["accepted_lapsed"]
            return f"accepted by {x['accepted_by']}, counted again ({x['why']}): {x['reason']}"
        return ""

    for f in (report.get("findings") or []) + (report.get("accepted") or []):
        w.writerow(
            [
                f["severity"],
                areas.get(f["area"], f["area"]),
                f.get("service_label", ""),
                f["title"],
                _cell(f["account"]),
                _cell(owners.get(f.get("account_id"), "")),
                "yes" if f["production"] else "no",
                f["region"],
                _cell(f["res"]),
                f["pct"],
                f["at_peak"],
                f["used"],
                f["limit"],
                f["unit"],
                f["days"],
                _cell(f["why"]),
                _cell(f["note"]),
                _cell(fixes.get(f["rule"], "")),
                _cell(status(f)),
            ]
        )
    return out.getvalue()
