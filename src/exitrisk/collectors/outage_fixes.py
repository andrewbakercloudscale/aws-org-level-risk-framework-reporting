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


def fault_fields(first: datetime | None, last: datetime | None, changed: datetime | None, change: str) -> dict:
    """The row fields the report judges by: when the fault happened, and a capacity change after it."""
    out = {}
    if last:
        out["first"], out["last"] = iso(first or last), iso(last)
    if last and changed and changed > last + HOUR:
        out["changed"], out["change"] = iso(changed), change
    return out


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
