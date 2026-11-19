"""The demo's SSM facts, for the SSM Abuse Review: a few accounts with a story, the rest quiet.

* legacy-batch-prod: an IAM user's access key that runs commands, used from the internet, and refused once;
* digital-channels-prod: a pipeline runner whose role opens a shell on every server, used from the runner to
  command others, and a tunnel through a server;
* shared-network-prod: 140 servers in the data centre under SSM, with a role that can command them all;
* payments-core-prod: a support permission set named read-only that can open a shell on every server;
* everywhere: administrators and the platform team who can, patching and Inspector run by SSM itself.
"""

from __future__ import annotations

REGION = "eu-west-1"
ALL = ["run", "onprem", "session", "params"]


def _holder(who: str, kind: str, can: list[str], admin: bool = False, profiles: list[str] | None = None,
            read_named: bool = False, outside: bool = False) -> dict:  # fmt: skip
    role = who.split(" ", 2)[-1]
    return {"who": who, "role": role, "kind": kind, "can": can, "admin": admin, "read_named": read_named,
            "outside": outside, "profiles": profiles or []}  # fmt: skip


def _row(call: str, kind: str, who: str, n: int, last: str, first: str = "", doc: str = "", code: str = "",
         where: str = "private", ips: list[str] | None = None, servers: int = 0, every: bool = False,
         aims: list[str] | None = None, account: str = "") -> dict:  # fmt: skip
    return {"call": call, "kind": kind, "who": who, "from": account, "doc": doc, "code": code, "where": where,
            "ips": ips or [], "n": n, "servers": servers, "every": every, "aims": aims or [], "first": first or last,
            "last": last, "shared": [], "role": ""}  # fmt: skip


def add(checked: dict, accounts: list[dict]) -> dict:
    names = {a["id"]: a["name"] for a in accounts}
    for i, (aid, res) in enumerate(checked.items()):
        name = names.get(aid, "")
        f = res.setdefault("facts", {})
        ec2 = 4 + (i * 7) % 23
        holders = [
            _holder("permission set AWSAdministratorAccess", "person", ALL, admin=True),
            _holder("permission set PlatformOperations", "person", ["run", "onprem", "session", "params"]),
            _holder("permission set ReadOnly", "person", ["params"]),
            _holder("role ssm-maintenance-window", "automation", ["run", "onprem", "params"]),
        ]
        rows = [_row("StartSession", "person", "permission set PlatformOperations (sipho.dlamini@example.com)",
                     3 + i % 5, "2026-11-12T09:14:00", "2026-09-02T10:02:00", where="internet",
                     ips=["196.25.1.17"], servers=1, aims=[f"i-0{aid[:8]}a1"], account=aid)]  # fmt: skip
        nodes = {"ec2": ec2, "hybrid": 0, "hybrid_online": 0, "platforms": {}, "roles": {}, "new": [], "new_count": 0}
        profiles = {f"i-0{aid[:8]}{k:02d}": f"arn:aws:iam::{aid}:instance-profile/app-instance" for k in range(ec2)}
        holders.append(_holder("role app-instance", "server", ["params"],
                               profiles=[f"arn:aws:iam::{aid}:instance-profile/app-instance"]))  # fmt: skip
        if "legacy" in name:
            holders.append(_holder("IAM user batch-deployer", "key", ["run", "session", "params"]))
            rows += [
                _row("SendCommand", "key", "IAM user batch-deployer", 3, "2026-11-16T22:41:00", "2026-11-14T23:05:00",
                     doc="AWS-RunShellScript", where="internet", ips=["45.83.64.11"], servers=6,
                     aims=[f"i-0{aid[:8]}00, i-0{aid[:8]}01, i-0{aid[:8]}02 and 3 more"], account=aid),
                _row("StartSession", "key", "IAM user batch-deployer", 2, "2026-11-16T22:37:00", code="AccessDenied",
                     where="internet", ips=["45.83.64.11"], servers=1, aims=[f"i-0{aid[:8]}04"], account=aid),
            ]  # fmt: skip
        if "digital-channels-prod" in name:
            runner = f"arn:aws:iam::{aid}:instance-profile/ci-runner"
            for k in range(3):
                profiles[f"i-0{aid[:8]}c{k}"] = runner
            holders.append(_holder("role ci-runner", "server", ["run", "session", "params"], profiles=[runner]))
            rows += [
                _row("SendCommand", "server", f"role ci-runner on i-0{aid[:8]}c0", 41, "2026-11-17T14:02:00",
                     "2026-08-21T08:30:00", doc="AWS-RunShellScript", servers=4,
                     aims=[f"i-0{aid[:8]}03, i-0{aid[:8]}04, i-0{aid[:8]}05 and 1 more"], account=aid),
                _row("StartSession", "server", f"role ci-runner on i-0{aid[:8]}c1", 2, "2026-11-15T03:12:00",
                     doc="AWS-StartPortForwardingSessionToRemoteHost", servers=1, aims=[f"i-0{aid[:8]}07"],
                     account=aid),
            ]  # fmt: skip
        if "shared-network" in name:
            nodes.update({"hybrid": 140, "hybrid_online": 131, "platforms": {"Windows": 96, "Linux": 44},
                          "roles": {"SSMHybridServers": 140}, "new_count": 3,
                          "new": [{"id": f"mi-0{aid[:6]}{k}e5f6a7b8", "name": f"DC1-APP{k:02d}",
                                   "ip": f"10.200.4.{20 + k}", "at": f"2026-11-1{k}T10:00:00+00:00",
                                   "platform": "Windows"} for k in range(3)]})  # fmt: skip
            holders.append(_holder("role SSMHybridServers", "automation", ["run", "onprem", "params"]))
            rows.append(_row("CreateActivation", "automation", "role hybrid-onboarding", 3, "2026-11-13T09:58:00",
                             "2026-11-10T09:55:00", account=aid))  # fmt: skip
            rows[-1]["role"] = "SSMHybridServers"
        if "payments-core-prod" in name:
            holders.append(_holder("permission set PaymentsSupport-Read", "person", ["session", "params"],
                                   read_named=True))  # fmt: skip
            rows.append(_row("SendCommand", "person", "permission set PlatformOperations (lerato.m@example.com)", 1,
                             "2026-11-03T19:20:00", doc="AWS-RunShellScript", where="internet",
                             ips=["196.25.1.17"], every=True, aims=["InstanceIds=*"], account=aid))  # fmt: skip
        f["ssm_holders"] = holders
        f.setdefault("instance_profiles", {})[REGION] = {**(f.get("instance_profiles") or {}).get(REGION, {}),
                                                          **profiles}  # fmt: skip
        f["ssm_abuse"] = {REGION: {
            "nodes": nodes,
            "activity": {"read": True, "days": 90, "rows": rows,
                         "events": {"SendCommand": {"n": 180 + i, "service": 170 + i, "cut": False},
                                    "StartSession": {"n": 4, "service": 0, "cut": False}}},
            "securityhub": {"read": True, "public": ["batch-restart"] if "legacy" in name else [],
                            "sharing": "legacy" in name},
        }}  # fmt: skip
    return checked
