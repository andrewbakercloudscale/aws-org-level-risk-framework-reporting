"""Was a failure in the lookback window fixed since? For the faults Outage Risk reads as events (a cluster that
went red, calls throttled, a volume past what it was provisioned for), when each last happened and whether the
resource's capacity was changed after it: a domain resized, a quota raised, a table's capacity raised, a volume
modified. The report then leaves a fault fixed after it last happened out of the actions, and says so.

Read only, and only for resources with a fault: describe_domain_config and describe_domain_change_progress,
the Service Quotas request history, describe_table and describe_volumes_modifications. A read that fails leaves
the fault as it is: never fixed on a guess."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger(__name__)

HOUR = timedelta(hours=1)
# A fault every hour of which is this close to a change being applied happened during that change: an
# OpenSearch blue/green deployment can show the cluster red for an hour while shards move to the new nodes.
DURING_BEFORE = timedelta(hours=3)
DURING_AFTER = timedelta(hours=4)
DURING_SPAN = timedelta(hours=6)  # longer than this from first to last, and it is not one change
SEARCH_SIZE_OPTIONS = ("ClusterConfig", "EBSOptions")
SEARCH_CHANGE_OPTIONS = (*SEARCH_SIZE_OPTIONS, "EngineVersion")
QUOTA_DONE = ("CASE_CLOSED", "APPROVED")


def iso(when: datetime | None) -> str | None:
    return when.isoformat(timespec="minutes") if when else None


def hit_span(*series) -> tuple[datetime | None, datetime | None]:
    """The first and last hour any of the series was above zero (None, None when it never was)."""
    firsts = [s.first_hit for s in series if s is not None and s.first_hit]
    lasts = [s.last_hit for s in series if s is not None and s.last_hit]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def fault_fields(
    first: datetime | None, last: datetime | None, changed: datetime | None, change: str, now: datetime | None = None
) -> dict:
    """The row fields the report judges by: when the fault happened, how many days it has not happened since
    (``now`` given), and a capacity change after it."""
    out = {}
    if last:
        out["first"], out["last"] = iso(first or last), iso(last)
        if now:
            out["quiet_days"] = round(max((now - last - HOUR).total_seconds(), 0) / 86400, 1)
    if last and changed and changed > last + HOUR:
        out["changed"], out["change"] = iso(changed), change
    return out


HOURS_BATCH = 100  # queries a GetMetricData call: 100 x 840 hourly points is under its 100,800 datapoint cap
DAY = timedelta(days=1)
# A fault that fell away: after its last day at DROP_BIG of its worst day or more, at least DROP_DAYS whole
# days at under DROP_SHARE of its daily level before. A raise made outside Service Quotas (an Amazon Connect
# calls per second raise is a support case) shows only this way, and a few blips after it never go quiet.
DROP_BIG = 0.10
DROP_SHARE = 0.05
DROP_DAYS = 2


def points_at(cw, wanted: dict, start: datetime, end: datetime, period: int) -> dict:
    """{key: [(time, value)]} of a metric, for the few resources a finding names: the lookback's summary keeps
    no datapoints. ``wanted``: {key: (namespace, metric, {dimension: value}, statistic, ...)}. Not read: left out."""
    keys = list(wanted)
    points: dict = {}
    for at in range(0, len(keys), HOURS_BATCH):
        batch = {f"h{n}": k for n, k in enumerate(keys[at : at + HOURS_BATCH])}
        queries = [
            {
                "Id": qid,
                "MetricStat": {
                    "Metric": {
                        "Namespace": wanted[k][0],
                        "MetricName": wanted[k][1],
                        "Dimensions": [{"Name": n, "Value": v} for n, v in wanted[k][2].items()],
                    },
                    "Period": period,
                    "Stat": wanted[k][3],
                },
            }
            for qid, k in batch.items()
        ]
        kw: dict = {}
        try:
            while True:
                got = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end, **kw)
                for r in got.get("MetricDataResults") or []:
                    key = batch.get(r.get("Id"))
                    if key is not None:
                        points.setdefault(key, []).extend(
                            zip(r.get("Timestamps") or [], r.get("Values") or [], strict=True)
                        )
                if not got.get("NextToken"):
                    break
                kw = {"NextToken": got["NextToken"]}
        except (ClientError, BotoCoreError) as exc:
            log.info("outage: datapoints not read: %s", exc)
    return points


def hours_at(cw, wanted: dict, start: datetime, end: datetime, period: int) -> dict:
    """{key: (first, last)} hours a metric was at or above a threshold, for the few resources a finding names:
    the lookback's summary keeps only the peak, not when it was reached. ``wanted``: {key: (namespace,
    metric, {dimension: value}, statistic, threshold)}. A key not read, or never at the threshold, is left out."""
    hits = {k: [t for t, v in p if v >= wanted[k][4]] for k, p in points_at(cw, wanted, start, end, period).items()}
    return {k: (min(t), max(t)) for k, t in hits.items() if t}


def daily(points: list, start: datetime, end: datetime, stat: str) -> list[tuple[datetime, float]]:
    """Datapoints as one value a day from ``start``: their total (a day with none is 0: a fault count is only
    published when there is one), or their worst for a Maximum (a day with none is left out)."""
    days: dict[int, float] = {}
    total = stat == "Sum"
    if total:
        days = dict.fromkeys(range(int((end - start) / DAY) + 1), 0.0)
    for t, v in points:
        k = int((t - start) / DAY)
        days[k] = days.get(k, 0.0) + v if total else max(days.get(k, v), v)
    return [(start + k * DAY, v) for k, v in sorted(days.items()) if start + k * DAY < end]


def drop_fields(days: list[tuple[datetime, float]], now: datetime) -> dict:
    """The row fields for a fault that fell away (DROP_*): the day it dropped, how many days it has been low
    since, and its daily level before and since. {} when it did not drop, or is still at its level."""
    worst = max((v for _, v in days), default=0.0)
    if worst <= 0:
        return {}
    big = [i for i, (_, v) in enumerate(days) if v >= DROP_BIG * worst]
    first, last = big[0], big[-1]
    since = [v for _, v in days[last + 1 :]]
    dropped = days[last][0] + DAY
    low = (now - dropped) / DAY
    before = [v for _, v in days[first : last + 1]]
    level, after = sum(before) / len(before), sum(since) / len(since) if since else 0.0
    if low < DROP_DAYS or len(since) < DROP_DAYS or after > DROP_SHARE * level:
        return {}
    return {
        "dropped": iso(dropped),
        "low_days": round(low, 1),
        "before": round(level, 1),
        "since": round(after, 1),
        "burst": first == last,
    }


def series_since(cw, namespace: str, metric: str, dims: dict, stat: str, start: datetime, end: datetime, period: int):
    """One metric from ``start`` on, as a Series: the trend after a resize, not across it. None: not read."""
    from .outage import Series  # outage imports this module

    query = {
        "Id": "s0",
        "MetricStat": {
            "Metric": {
                "Namespace": namespace,
                "MetricName": metric,
                "Dimensions": [{"Name": n, "Value": v} for n, v in dims.items()],
            },
            "Period": period,
            "Stat": stat,
        },
    }
    points: list = []
    kw: dict = {}
    try:
        while True:
            got = cw.get_metric_data(
                MetricDataQueries=[query], StartTime=start, EndTime=end, ScanBy="TimestampAscending", **kw
            )
            for r in got.get("MetricDataResults") or []:
                points += zip(r.get("Timestamps") or [], r.get("Values") or [], strict=True)
            if not got.get("NextToken"):
                break
            kw = {"NextToken": got["NextToken"]}
    except (ClientError, BotoCoreError) as exc:
        log.info("outage: %s since %s not read: %s", metric, iso(start), exc)
        return None
    s = Series()
    for when, value in sorted(points):
        s.add(when, value)
    return s if s.n else None


def during(first: datetime | None, last: datetime | None, changes: list[tuple[datetime, str]]) -> str | None:
    """The change a short fault happened during, or None."""
    if not last or not first or last - first > DURING_SPAN:
        return None
    near = [(when, what) for when, what in changes if first - DURING_BEFORE <= when <= last + HOUR + DURING_AFTER]
    if not near:
        return None
    end = last + HOUR  # a datapoint stands for the hour after it

    def gap(c):  # how far the change is from the hours of the fault: 0 within them
        return max(first - c[0], c[0] - end, timedelta(0))

    when, what = min(near, key=gap)  # the change closest to the fault
    return f"{what} on {iso(when)}"


def search_changes(client, name: str) -> tuple[datetime | None, list[tuple[datetime, str]]]:
    """An OpenSearch domain's last resize (cluster or storage), and the changes it has a date for."""
    try:
        cfg = client.describe_domain_config(DomainName=name).get("DomainConfig") or {}
    except (ClientError, BotoCoreError) as exc:
        log.info("outage: domain config of %s not read: %s", name, exc)
        return None, []
    dates = {k: ((cfg.get(k) or {}).get("Status") or {}).get("UpdateDate") for k in SEARCH_CHANGE_OPTIONS}
    sized = [dates[k] for k in SEARCH_SIZE_OPTIONS if dates.get(k)]
    labels = {"ClusterConfig": "a cluster change", "EBSOptions": "a storage change", "EngineVersion": "an upgrade"}
    changes = [(when, labels[k]) for k, when in dates.items() if when]
    try:
        prog = client.describe_domain_change_progress(DomainName=name).get("ChangeProgressStatus") or {}
        if prog.get("StartTime"):
            changes.append((prog["StartTime"], "a configuration change"))
    except (ClientError, BotoCoreError):
        pass
    return (max(sized) if sized else None), changes


def quota_raises(client, service: str, match) -> datetime | None:
    """The last quota increase for the service whose name matches, granted (None: none, or not read)."""
    try:
        got = client.list_requested_service_quota_change_history(ServiceCode=service).get("RequestedQuotas") or []
    except (ClientError, BotoCoreError) as exc:
        log.info("outage: quota history for %s not read: %s", service, exc)
        return None
    done = [q.get("LastUpdated") for q in got if q.get("Status") in QUOTA_DONE and match(q.get("QuotaName") or "")]
    return max((d for d in done if d), default=None)


def table_raised(client, table: str, autoscaled: bool) -> tuple[datetime | None, str]:
    """When a DynamoDB table last went on demand, or (with no autoscaling, whose own raises are no fix) last had
    its capacity or an index's raised by hand. (None, "") when neither, or the table was not read."""
    try:
        t = client.describe_table(TableName=table).get("Table") or {}
    except (ClientError, BotoCoreError) as exc:
        log.info("outage: table %s not read: %s", table, exc)
        return None, ""
    found = []
    billing = t.get("BillingModeSummary") or {}
    if billing.get("BillingMode") == "PAY_PER_REQUEST" and billing.get("LastUpdateToPayPerRequestDateTime"):
        found.append((billing["LastUpdateToPayPerRequestDateTime"], "the table moved to on demand"))
    if not autoscaled and billing.get("BillingMode") != "PAY_PER_REQUEST":
        raised = [(t.get("ProvisionedThroughput") or {}).get("LastIncreaseDateTime")]
        raised += [
            (i.get("ProvisionedThroughput") or {}).get("LastIncreaseDateTime")
            for i in t.get("GlobalSecondaryIndexes") or []
        ]
        found += [(d, "the table's capacity was raised") for d in raised if d]
    return max(found, key=lambda x: x[0], default=(None, ""))


def table_capacity(client, table: str) -> dict[str, float] | None:
    """A DynamoDB table's provisioned units today, {"read": n, "write": n}: {} when it is on demand (no ceiling),
    None when it was not read. Today's setting, not the last datapoint of the provisioned capacity metric, which
    stops when a table goes on demand and so can be any value it had."""
    try:
        t = client.describe_table(TableName=table).get("Table") or {}
    except (ClientError, BotoCoreError) as exc:
        log.info("outage: table %s not read: %s", table, exc)
        return None
    if (t.get("BillingModeSummary") or {}).get("BillingMode") == "PAY_PER_REQUEST":
        return {}
    p = t.get("ProvisionedThroughput") or {}
    return {"read": float(p.get("ReadCapacityUnits") or 0), "write": float(p.get("WriteCapacityUnits") or 0)}


CONCURRENCY_EVENTS = ("PutFunctionConcurrency", "DeleteFunctionConcurrency")  # CloudTrail names carry a version


def concurrency_changed(client, function: str) -> datetime | None:
    """When a Lambda function's reserved concurrency was last set or removed, from CloudTrail's event history
    (90 days). None: not changed in it, or not read."""
    try:
        got = client.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": function}], MaxResults=50
        )
    except (ClientError, BotoCoreError) as exc:
        log.info("outage: changes to %s not read: %s", function, exc)
        return None
    hits = [
        e["EventTime"]
        for e in got.get("Events") or []
        if e.get("EventTime") and e.get("EventName", "").startswith(CONCURRENCY_EVENTS)
    ]
    return max(hits, default=None)


def volumes_modified(client, volumes: list[str]) -> dict[str, datetime]:
    """{volume: when its last size, IOPS or throughput change started}, for the volumes asked about."""
    out: dict[str, datetime] = {}
    for at in range(0, len(volumes), 200):
        try:
            flt = [
                {"Name": "volume-id", "Values": volumes[at : at + 200]}
            ]  # by filter: a volume never changed is no error
            got = client.describe_volumes_modifications(Filters=flt).get("VolumesModifications")
        except (ClientError, BotoCoreError) as exc:
            log.info("outage: volume modifications not read: %s", exc)
            continue
        for m in got or []:
            if m.get("ModificationState") in ("completed", "optimizing") and m.get("StartTime"):
                vid = m["VolumeId"]
                out[vid] = max(out.get(vid, m["StartTime"]), m["StartTime"])
    return out
