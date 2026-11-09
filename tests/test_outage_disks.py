import re
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

from exitrisk.collectors import healthcheck as hc
from exitrisk.collectors import outage_disks as d
from exitrisk.collectors.outage import OutageCtx, Series
from exitrisk.outage import disk_sight
from exitrisk.scanner import ScanParams

DF_K = """Filesystem     Type     1024-blocks     Used Available Capacity Mounted on
devtmpfs       devtmpfs     4096        0      4096       0% /dev
tmpfs          tmpfs      786600     1064    785536       1% /run
/dev/nvme0n1p1 xfs      20959212 18225008   2734204      87% /
tmpfs          tmpfs     2097152  2097152         0     100% /tmp
overlay        overlay  20959212 18225008   2734204      87% /var/lib/containerd/x/rootfs
/dev/nvme2n1   ext4     10000000  1000000   9000000      10% /var/lib/kubelet/pods/abc/volumes
"""
DF_I = """Filesystem     Type     Inodes  IUsed   IFree IUse% Mounted on
/dev/nvme0n1p1 xfs     10484672 10400000 84672  100% /
vfat           vfat          0       0      0     - /boot/efi
"""


def _awk(line: str, sample: str) -> str:
    prog = line.split("awk ", 1)[1]
    return subprocess.run(["/bin/sh", "-c", f"awk {prog}"], input=sample, capture_output=True, text=True).stdout


def test_linux_script_keeps_real_disks_only():
    got = d.parse_df(_awk(d.LINUX_DF[4], DF_K))
    assert [(x["mount"], x["pct"]) for x in got] == [("/", 87.0), ("/tmp", 100.0)]
    inodes = d.parse_df(_awk(d.LINUX_DF[5], DF_I))
    assert [(x["kind"], x["mount"], x["pct"]) for x in inodes] == [("I", "/", 99.2)]


def test_script_is_read_only_and_bounded():
    text = "\n".join(d.LINUX_DF)
    assert "df -PTlk" in text and "df -PTli" in text  # local file systems only: no hang on NFS or EFS
    assert "timeout 20" in text and "nice -n 19" in text and "ionice -c3" in text
    for word in ("rm ", ">>", "mv ", "tee", "chmod", "kill", "mkfs", "dd ", "sudo"):
        assert word not in text
    shell = re.sub(r"awk '[^']*'", "awk", text)  # the awk programs compare with >, they redirect nothing
    assert not re.search(r">\s*(?!/dev/null|&1)[/\w$]", shell)  # writes to no file
    assert "-OperationTimeoutSec 20" in "\n".join(d.WINDOWS_DF)


def test_parse_df_ignores_noise():
    assert d.parse_df("hello\nD|/|xfs|x|1|2\nD|/a|xfs|10|0|0\nD|/b|xfs|10|5|5") == [
        {"kind": "D", "mount": "/b", "type": "xfs", "total": 10.0, "used": 5.0, "free": 5.0, "pct": 50.0}
    ]


class FakeSSM:
    """Run Command, answering each instance as ``answers`` says."""

    def __init__(self, managed, answers, deny=False):
        self.managed, self.answers, self.deny = managed, answers, deny
        self.sent: list[list[str]] = []
        self.cmds: dict[str, list[str]] = {}

    def can_paginate(self, op):
        return False

    def describe_instance_information(self, **kw):
        return {"InstanceInformationList": self.managed}

    def send_command(self, **kw):
        if self.deny:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "SendCommand")
        assert kw["Comment"] and kw["MaxConcurrency"] == d.DF_CONCURRENCY and kw["TimeoutSeconds"] >= 30
        cid = f"c{len(self.sent)}"
        self.sent.append(kw["InstanceIds"])
        self.cmds[cid] = kw["InstanceIds"]
        return {"Command": {"CommandId": cid}}

    def list_command_invocations(self, CommandId, Details):
        t0 = datetime(2026, 11, 9, tzinfo=timezone.utc)
        out = []
        for iid in self.cmds[CommandId]:
            status, text, secs = self.answers[iid]
            plugin = {
                "Output": text,
                "ResponseStartDateTime": t0,
                "ResponseFinishDateTime": t0 + timedelta(seconds=secs),
            }
            out.append({"InstanceId": iid, "Status": status, "StatusDetails": status, "CommandPlugins": [plugin]})
        return {"CommandInvocations": out}


class FakeEC2:
    def __init__(self, instances):
        self.instances = instances

    def can_paginate(self, op):
        return False

    def describe_instances(self, **kw):
        return {"Reservations": [{"Instances": self.instances}]}


class FakeSession:
    def __init__(self, **clients):
        self.clients = clients

    def client(self, name, region_name=None, config=None):
        return self.clients[name]


def _ctx(ssm, instances, df=True, metrics=None):
    ctx = OutageCtx(FakeSession(ssm=ssm, ec2=FakeEC2(instances)), "111111111111", ["eu-west-1"], {"df": df})
    ctx._metrics["eu-west-1"] = metrics or {"disk_used": {}, "win_disk_free": {}}
    return ctx


INSTANCES = [
    {"InstanceId": "i-a", "Tags": [{"Key": "Name", "Value": "app1"}]},
    {"InstanceId": "i-b", "Tags": [{"Key": "Name", "Value": "app2"}]},
    {"InstanceId": "i-c", "Tags": [{"Key": "eks:cluster-name", "Value": "c"}]},
]
MANAGED = [{"InstanceId": i, "PlatformType": "Linux", "ComputerName": i} for i in ("i-a", "i-b")]
OUT = "D|/|xfs|100|95|5\nD|/tmp|tmpfs|100|10|90\nI|/|xfs|100|99|1\n"


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(d.time, "sleep", lambda s: None)


def test_df_canary_then_rest_and_rows():
    ssm = FakeSSM(MANAGED, {"i-a": ("Success", OUT, 1), "i-b": ("Success", OUT, 1)})
    ctx = _ctx(ssm, INSTANCES)
    d.task_disks(ctx, "eu-west-1")
    assert ssm.sent == [["i-a"], ["i-b"]]  # one server first, then the rest
    rules = sorted((r["rule"], r["res"]) for r in ctx.rows)
    assert ("disk_full", "app1 (i-a) /") in rules and ("inodes_full", "app2 (i-b) /") in rules
    assert ("disk_full", "app1 (i-a) /tmp") not in rules  # 10% full: counted, not kept
    facts = ctx.r.facts["disks"]["eu-west-1"]
    assert facts == {"running": 3, "seen": 2, "blind": 1, "blind_fixed": 0, "examples": []}
    assert ctx.r.finish()["disks_df"]["status"] == "pass"


def test_canary_failure_stops_the_rest():
    ssm = FakeSSM(MANAGED, {"i-a": ("Failed", "", 1), "i-b": ("Success", OUT, 1)})
    ctx = _ctx(ssm, INSTANCES)
    d.task_disks(ctx, "eu-west-1")
    assert ssm.sent == [["i-a"]]
    assert ctx.r.finish()["disks_df"]["status"] == "unknown"
    assert ctx.r.facts["df_stopped"]["eu-west-1"]["canary"] == "i-a"


def test_slow_canary_stops_the_rest():
    ssm = FakeSSM(MANAGED, {"i-a": ("Success", OUT, 26), "i-b": ("Success", OUT, 1)})
    ctx = _ctx(ssm, INSTANCES)
    d.task_disks(ctx, "eu-west-1")
    assert ssm.sent == [["i-a"]]
    assert ctx.r.facts["df_stopped"]["eu-west-1"]["why"] == "took too long"


def test_refused_send_is_a_permission_gap_not_a_pass():
    ctx = _ctx(FakeSSM(MANAGED, {}, deny=True), INSTANCES)
    d.task_disks(ctx, "eu-west-1")
    assert "AccessDenied" in ctx.r.finish()["disks_df"]["note"] + str(ctx.r.finish()["disks_df"])
    assert "ssm:SendCommand" in ctx.issues[0].hint
    assert ctx.r.facts["disks"]["eu-west-1"]["blind"] == 3


def test_off_by_default_sends_nothing():
    ssm = FakeSSM(MANAGED, {})
    ctx = _ctx(ssm, INSTANCES, df=False)
    d.task_disks(ctx, "eu-west-1")
    assert ssm.sent == [] and "disks_df" not in ctx.r.finish()
    assert ctx.r.facts["disks"]["eu-west-1"]["blind_fixed"] == 2


def test_agent_mounts_not_repeated_and_windows_read():
    linux = Series()
    linux.add(datetime.now(timezone.utc), 50.0)
    win = Series()
    win.add(datetime.now(timezone.utc), 4.0)  # 4% free
    m = {"disk_used": {"i-a|/": linux}, "win_disk_free": {"i-b|C:": win, "i-b|_Total": win}}
    ssm = FakeSSM(MANAGED, {"i-a": ("Success", OUT, 1), "i-b": ("Success", "", 1)})
    ctx = _ctx(ssm, INSTANCES, metrics=m)
    d.task_disks(ctx, "eu-west-1")
    res = [r["res"] for r in ctx.rows if r["rule"] == "disk_full"]
    assert "app1 (i-a) /" not in res  # the agent gave it
    assert "app2 (i-b) C:" in res and not any("_Total" in r for r in res)


def test_disk_sight_sums_regions():
    facts = {
        "disks": {"a": {"running": 3, "seen": 1, "blind": 2, "blind_fixed": 1, "examples": ["x"]},
                  "b": {"running": 1, "seen": 1, "blind": 0, "blind_fixed": 0, "examples": []}},
        "df_stopped": {"a": {"canary": "i-1", "why": "Failed"}},
    }  # fmt: skip
    got = disk_sight(facts)
    assert got["running"] == 4 and got["blind"] == 2 and got["examples"] == ["x"] and got["df_stopped"] == ["a: Failed"]


def test_df_needs_the_outage_checks():
    with pytest.raises(ValueError):
        ScanParams(outage_df=True).validate()
    ScanParams(outage=True, outage_df=True).validate()


@pytest.mark.parametrize(
    "line,hit",
    [
        ("write /tmp/EVPJ0003C.part: No space left on device", True),
        ("java.io.IOException: No space left on device", True),
        ("There is not enough space on the disk.", True),
        ("errno ENOSPC while writing", True),
        ("ERROR: could not extend file: disk quota exceeded", True),
        ("disk usage 40%, plenty of space", False),
        ("diskfullness metric published", False),
    ],
)
def test_disk_full_log_pattern(line, hit):
    body = hc.DISK_FULL_RE.strip("/")
    assert bool(re.search(body.replace("(?i)", ""), line, re.I)) is hit
