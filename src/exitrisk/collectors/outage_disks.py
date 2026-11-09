"""Disk space inside each server: how full every mount is, and which servers nobody can see.

AWS sees a volume's size, never how full the file system on it is. That is known only where the server
reports it: the CloudWatch agent (disk_used_percent on Linux, LogicalDisk % Free Space on Windows), or by
asking the server. This task:

* reads Windows free space from the agent (Linux is read with the other metrics, in task_ec2);
* when the scan was started with the df option, and only then, asks each server that Systems Manager
  manages for its disk and inode use with ``df`` (PowerShell on Windows) through SSM Run Command;
* counts the running servers that report their disks neither way, so a blind server is never a pass.

Run Command is not read only: it runs a command on the server, as root, and CloudTrail records it. The
command is kept as harmless as it can be:

* it only reads: ``df`` on local file systems (``-l``), so a hung network mount (NFS, EFS) cannot hang it;
* at the lowest CPU and I/O priority (``nice``, ``ionice``), stopped after 20 s (``timeout``), with
  Run Command's own limit of 30 s behind that;
* it first runs on one server in the region (a canary) and goes on to the others only if that one
  answered cleanly and quickly; at most ``DF_CONCURRENCY`` servers run it at a time;
* it writes nothing but Run Command's own record of the run, and prints a few lines per mount.
"""

from __future__ import annotations

import time

from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import with_backoff
from ..issues import Issue, describe_exception
from ..logging_config import get_logger
from .assurance import _code, _pages
from .outage import REGION_TASKS, OutageCtx, _filling

log = get_logger("outage")

# Tags that mark a server something else replaces (Auto Scaling, EKS managed nodes, Karpenter): one that fills
# its disk is usually replaced, so it is counted apart from the servers someone looks after.
SCALED_TAGS = ("aws:autoscaling:", "eks:", "aws:eks:", "kubernetes.io/cluster/", "karpenter.sh/", "karpenter.k8s.aws/")
DF_MAX = 1000  # servers asked per region
DF_BATCH = 50  # the most instance ids one SendCommand takes
DF_CONCURRENCY = "10"  # servers running it at once within one command
DF_TIMEOUT = 30  # seconds Run Command lets the command run (its minimum)
DF_WAIT = 150  # seconds to wait for every answer in a region
CANARY_SECONDS = 25.0  # the canary must answer within this, or the rest are not asked
COMMENT = "AWS Cloud Risk Review: disk use (df), read only"
DONE = {"Success", "Failed", "TimedOut", "Cancelled", "Undeliverable", "Terminated"}

# Local file systems only (-l): a hung network mount cannot hang df. Pseudo and container layers left out,
# as are the kubelet and container runtime mounts, which repeat the node's own disks.
_SKIP_TYPES = "overlay|squashfs|devtmpfs|proc|sysfs|nsfs|cgroup|cgroup2|autofs|tracefs|debugfs|securityfs|pstore|bpf"
_SKIP_MOUNTS = r"^/(proc|sys|dev|run|snap|var/lib/(kubelet|docker|containerd))(/|$)"
_KEEP = f"$2!~/^({_SKIP_TYPES})$/ && $7!~/{_SKIP_MOUNTS.replace('/', chr(92) + '/')}/"
LINUX_DF = [
    "export LC_ALL=C",
    "T=''; command -v timeout >/dev/null 2>&1 && T='timeout 20'",
    "N=''; command -v nice >/dev/null 2>&1 && N='nice -n 19'",
    "I=''; command -v ionice >/dev/null 2>&1 && I='ionice -c3 -t'",
    f'$T $N $I df -PTlk 2>/dev/null | awk \'NR>1 && {_KEEP} {{print "D|"$7"|"$2"|"$3"|"$4"|"$5}}\'',
    f'$T $N $I df -PTli 2>/dev/null | awk \'NR>1 && $3>0 && {_KEEP} {{print "I|"$7"|"$2"|"$3"|"$4"|"$5}}\'',
    "exit 0",
]
WINDOWS_DF = [
    "$ErrorActionPreference = 'Stop'",
    "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 20 | ForEach-Object {",
    "  $s = [math]::Round($_.Size / 1KB); $f = [math]::Round($_.FreeSpace / 1KB)",
    "  'D|' + $_.DeviceID + '|' + $_.FileSystem + '|' + $s + '|' + ($s - $f) + '|' + $f }",
]
DOCUMENTS = {"Linux": ("AWS-RunShellScript", LINUX_DF), "Windows": ("AWS-RunPowerShellScript", WINDOWS_DF)}


def parse_df(text: str) -> list[dict]:
    """Each mount df printed: {kind "D" (space) or "I" (inodes), mount, type, total, used, free, pct}."""
    out = []
    for line in (text or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) != 6 or parts[0] not in ("D", "I"):
            continue
        try:
            total, used, free = (float(x) for x in parts[3:6])
        except ValueError:
            continue
        if used + free <= 0:
            continue
        # As df works it out: blocks reserved for root count as neither used nor free.
        pct = 100.0 * used / (used + free)
        out.append({"kind": parts[0], "mount": parts[1], "type": parts[2], "total": total, "used": used,
                    "free": free, "pct": round(pct, 1)})  # fmt: skip
    return out


def _gib(kb: float) -> float:
    return round(kb / 1024**2, 1)


def _servers(ctx: OutageCtx, region: str) -> dict[str, dict]:
    ec2 = ctx.client("ec2", region)
    out = {}
    for r in _pages(ec2, "describe_instances", "Reservations",
                    Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):  # fmt: skip
        for i in r.get("Instances") or []:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags") or []}
            out[i["InstanceId"]] = {
                "name": tags.get("Name", ""),
                "scaled": any(k.startswith(SCALED_TAGS) for k in tags),
                "windows": (i.get("Platform") or "").lower() == "windows",
            }
    return out


def _label(servers: dict, iid: str, fallback: str = "") -> str:
    name = (servers.get(iid) or {}).get("name") or fallback
    return f"{name} ({iid})" if name and name != iid else iid


def _windows_agent(ctx: OutageCtx, region: str, servers: dict, m: dict) -> set[str]:
    """Windows drives the agent reports, as disk_full rows; the servers it reports for."""
    seen = set()
    for key, s in (m.get("win_disk_free") or {}).items():
        iid, _, drive = key.partition("|")
        if not s.n or drive.lower() == "_total":
            continue
        seen.add(iid)
        if iid in servers:
            _filling(ctx, "disk_full", f"{_label(servers, iid)} {drive}", region, min(100.0 - s.last, 100.0),
                     -s.slope(), note="from the CloudWatch agent")  # fmt: skip
    return seen


def _send(ssm, doc: str, lines: list[str], ids: list[str]) -> str:
    got = with_backoff(
        ssm.send_command,
        InstanceIds=ids,
        DocumentName=doc,
        Parameters={"commands": lines, "executionTimeout": [str(DF_TIMEOUT)]},
        TimeoutSeconds=max(DF_TIMEOUT, 30),
        Comment=COMMENT,
        MaxConcurrency=DF_CONCURRENCY,
        MaxErrors="100%",
    )
    return got["Command"]["CommandId"]


def _collect(ssm, commands: dict[str, list[str]], deadline: float) -> dict[str, dict]:
    """{instance: {status, output, seconds}} once every instance answered or the deadline passed."""
    out: dict[str, dict] = {}
    waiting = {cid: set(ids) for cid, ids in commands.items()}
    while any(waiting.values()) and time.monotonic() < deadline:
        time.sleep(3)
        for cid, ids in waiting.items():
            if not ids:
                continue
            for inv in _pages(ssm, "list_command_invocations", "CommandInvocations", CommandId=cid, Details=True):
                iid, status = inv.get("InstanceId"), inv.get("Status")
                if iid not in ids or status not in DONE:
                    continue
                plugin = (inv.get("CommandPlugins") or [{}])[0]
                text = plugin.get("Output") or ""
                if "--output truncated--" in text:
                    full = with_backoff(ssm.get_command_invocation, CommandId=cid, InstanceId=iid)
                    text = full.get("StandardOutputContent") or text
                start, end = plugin.get("ResponseStartDateTime"), plugin.get("ResponseFinishDateTime")
                secs = (end - start).total_seconds() if start and end else None
                out[iid] = {"status": status, "output": text, "seconds": secs,
                            "detail": inv.get("StatusDetails") or status}  # fmt: skip
                ids.discard(iid)
    for ids in waiting.values():
        for iid in ids:
            out.setdefault(iid, {"status": "NoAnswer", "output": "", "seconds": None, "detail": "no answer in time"})
    return out


def _run_df(ctx: OutageCtx, region: str, targets: dict[str, str]) -> dict[str, dict]:
    """df on each target {instance: platform}: a canary first, the rest only if it answered cleanly."""
    ssm = ctx.client("ssm", region)
    ordered = sorted(targets, key=lambda i: (targets[i] != "Linux", i))
    canary, rest = ordered[0], ordered[1:]
    doc, lines = DOCUMENTS[targets[canary]]
    first = _collect(ssm, {_send(ssm, doc, lines, [canary]): [canary]}, time.monotonic() + DF_WAIT)
    got = first[canary]
    slow = got["seconds"] is not None and got["seconds"] > CANARY_SECONDS
    if got["status"] != "Success" or slow or not parse_df(got["output"]):
        why = "took too long" if slow else got["detail"]
        ctx.r.unknown("disks_df", f"df canary {why} in {region}")
        ctx.r.fact("df_stopped", {"canary": canary, "why": why}, region)
        return first
    commands: dict[str, list[str]] = {}
    for platform in ("Linux", "Windows"):
        ids = [i for i in rest if targets[i] == platform]
        doc, lines = DOCUMENTS[platform]
        for at in range(0, len(ids), DF_BATCH):
            batch = ids[at : at + DF_BATCH]
            commands[_send(ssm, doc, lines, batch)] = batch
    return {**first, **_collect(ssm, commands, time.monotonic() + DF_WAIT)}


def _df(ctx: OutageCtx, region: str, servers: dict, agent: set[tuple[str, str]]) -> set[str]:
    """df through Run Command on the servers SSM manages and can reach now; the servers it answered for."""
    ssm = ctx.client("ssm", region)
    managed = _pages(ssm, "describe_instance_information", "InstanceInformationList",
                     Filters=[{"Key": "PingStatus", "Values": ["Online"]}])  # fmt: skip
    targets = {
        m["InstanceId"]: m["PlatformType"]
        for m in managed
        if m.get("PlatformType") in DOCUMENTS and (m["InstanceId"] in servers or m["InstanceId"].startswith("mi-"))
    }
    names = {m["InstanceId"]: m.get("ComputerName") or "" for m in managed}
    if len(targets) > DF_MAX:
        ctx.r.fact("df_cut", len(targets) - DF_MAX, region)
        targets = dict(sorted(targets.items())[:DF_MAX])
    if not targets:
        ctx.r.ok("disks_df")
        return set()
    try:
        answers = _run_df(ctx, region, targets)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        ctx.r.unknown("disks_df", f"{_code(exc) or 'error'} in {region}")
        if (_code(exc) or "").lower().startswith("accessdenied"):
            hint = ("The scan's sign-in may not run commands: it needs ssm:SendCommand on the documents "
                    "AWS-RunShellScript and AWS-RunPowerShellScript, and ssm:ListCommandInvocations. Without it, "
                    "only servers with the CloudWatch agent report their disks.")  # fmt: skip
        ctx.issue(Issue("warning", "outage", f"df on servers in {region}: {msg}", hint,
                        account_id=ctx.account_id, region=region, error_code=code))  # fmt: skip
        return set()
    seen, failed = set(), []
    for iid, got in answers.items():
        mounts = parse_df(got["output"]) if got["status"] == "Success" else []
        if not mounts:
            if iid in targets and got["status"] not in ("Success",):
                failed.append(f"{_label(servers, iid, names.get(iid, ''))}: {got['detail']}")
            continue
        seen.add(iid)
        label = _label(servers, iid, names.get(iid, ""))
        for d in mounts:
            note = f"{d['type']}; from df via Run Command"
            res = f"{label} {d['mount']}"
            if d["kind"] == "I":
                ctx.add("inodes_full", res, region, pct=d["pct"], used=int(d["used"]),
                        limit=int(d["used"] + d["free"]), unit="inodes", note=note)  # fmt: skip
            elif (iid, d["mount"]) not in agent:  # the agent already gave this mount, with its trend
                ctx.add("disk_full", res, region, pct=d["pct"], used=_gib(d["used"]),
                        limit=_gib(d["used"] + d["free"]), unit="GiB", note=note)  # fmt: skip
    if failed:
        ctx.r.unknown("disks_df", f"df did not answer on {len(failed)} server(s) in {region}")
        ctx.r.fact("df_failed", failed[:20], region)
    else:
        ctx.r.ok("disks_df")
    return seen


def task_disks(ctx: OutageCtx, region: str) -> None:
    servers = _servers(ctx, region)
    m = ctx.metrics(region)
    agent_mounts = {tuple(k.split("|", 1)) for k, s in (m.get("disk_used") or {}).items() if s.n}
    seen = {iid for iid, _ in agent_mounts} | _windows_agent(ctx, region, servers, m)
    ctx.r.ok("disks")
    if ctx.df:
        seen |= _df(ctx, region, servers, agent_mounts)
    blind = [iid for iid in servers if iid not in seen]
    fixed = [iid for iid in blind if not servers[iid]["scaled"]]
    ctx.r.fact(
        "disks",
        {
            "running": len(servers),
            "seen": len([i for i in servers if i in seen]),
            "blind": len(blind),
            "blind_fixed": len(fixed),
            "examples": [_label(servers, i) for i in sorted(fixed)[:10]],
        },
        region,
    )


REGION_TASKS.append(("server disks", ("disks",), task_disks, None))
