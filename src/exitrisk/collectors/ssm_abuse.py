"""Signs of Systems Manager (SSM) abuse in one member account, for the SSM Abuse Review.

SSM runs commands and opens shells on every server it manages (EC2 instances, and servers in the data
centre registered as hybrid nodes, mi-...), as root or SYSTEM, without SSH, RDP or an open port. Whoever can
call ssm:SendCommand or ssm:StartSession on a server owns it. Attackers use that three ways: a stolen key or
role runs commands on every server at once; a break-in on one server uses that server's own role to reach the
others; and a hybrid activation or a shared document gives a foothold that outlives the first one.

Read here, with calls the scan's role already has:

* the managed nodes (ssm:DescribeInstanceInformation): EC2 and on premises, their role, when registered;
* who can run commands, open sessions and read Parameter Store, from the IAM policies the IAM task reads
  (iam:GetAccountAuthorizationDetails), boundaries included, conditions treated as a restriction;
* what was done in the last 90 days (cloudtrail:LookupEvents): commands, sessions, hybrid activations,
  documents shared and associations, by whom, from where, and what was refused;
* Security Hub's SSM controls where Security Hub runs (documents public, public sharing not blocked).

Nothing here reads a command's text (CloudTrail hides it), a parameter's value or a session's output.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import with_backoff

DAYS = 90  # CloudTrail event history keeps 90 days of management events
NEW_DAYS = 30  # a hybrid node registered this recently is listed by name
ROWS = 60  # activity rows kept per region
PAGES = {"SendCommand": 6, "StartSession": 6, "CreateActivation": 2, "ModifyDocumentPermission": 2,
         "CreateAssociation": 2, "UpdateAssociation": 2}  # fmt: skip
SHELL_DOCS = ("AWS-RunShellScript", "AWS-RunPowerShellScript", "AWS-RunRemoteScript", "AWS-RunDocument")
WIDE = 20  # a command sent to this many servers, or to all of them, by one caller at once
# Session documents that tunnel from the server to somewhere else: a way past the network's controls.
TUNNEL_DOCS = ("AWS-StartPortForwardingSessionToRemoteHost", "AWS-StartPortForwardingSessionToSocket")
READ_NAME = re.compile(r"(^|[-_ ])(read|readonly|read-only|viewer?|view-?only|audit(or)?|observer)($|[-_ ])", re.I)
SH_CONTROLS = {"SSM.4": "public", "SSM.7": "sharing"}  # documents public; public sharing not blocked


# ----------------------------------------------------------------------------- nodes


def node_summary(infos: list[dict], now: datetime) -> dict:
    """What SSM manages in one region: EC2 instances and hybrid (on-premises) nodes, with their roles."""
    out = {"ec2": 0, "hybrid": 0, "hybrid_online": 0, "platforms": {}, "roles": {}, "new": []}
    cutoff = now - timedelta(days=NEW_DAYS)
    for i in infos:
        hybrid = i.get("ResourceType") == "ManagedInstance" or str(i.get("InstanceId", "")).startswith("mi-")
        out["hybrid" if hybrid else "ec2"] += 1
        if not hybrid:
            continue
        out["hybrid_online"] += 1 if i.get("PingStatus") == "Online" else 0
        plat = i.get("PlatformType") or "Unknown"
        out["platforms"][plat] = out["platforms"].get(plat, 0) + 1
        role = (i.get("IamRole") or "").split("/")[-1]
        if role:
            out["roles"][role] = out["roles"].get(role, 0) + 1
        when = i.get("RegistrationDate")
        if isinstance(when, datetime):
            when = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
            if when >= cutoff:
                out["new"].append({"id": i.get("InstanceId"), "name": i.get("ComputerName") or i.get("Name") or "",
                                   "ip": i.get("IPAddress") or "", "at": when.isoformat(timespec="seconds"),
                                   "platform": plat})  # fmt: skip
    out["new"].sort(key=lambda x: x["at"], reverse=True)
    out["new_count"] = len(out["new"])
    out["new"] = out["new"][:20]
    return out


# ----------------------------------------------------------------------------- who did it


def caller(ev: dict, account: str, org: set[str]) -> dict:
    """{kind, who, account}: the identity behind one CloudTrail event. Kinds: service (SSM itself, patching,
    Inspector), person (an SSO permission set or a federated person), key (an IAM user's access key), root,
    server (a role used from an EC2 instance or a hybrid node), outside (an account outside the organisation),
    automation (any other role)."""
    u = ev.get("userIdentity") or {}
    t = u.get("type") or ""
    acct = str(u.get("accountId") or account)
    arn = u.get("arn") or ""
    via = str(u.get("invokedBy") or "")
    if (
        t == "AWSService"
        or via.endswith(".amazonaws.com")
        or str(ev.get("sourceIPAddress", "")).endswith(".amazonaws.com")
    ):
        return {"kind": "service", "who": via or str(ev.get("sourceIPAddress") or "AWS"), "account": acct}
    outside = acct != account and acct not in org
    if t == "Root":
        return {"kind": "outside" if outside else "root", "who": "root user", "account": acct}
    if t == "IAMUser":
        name = u.get("userName") or arn.rsplit("/", 1)[-1]
        return {"kind": "outside" if outside else "key", "who": f"IAM user {name}", "account": acct}
    if t == "AssumedRole" and ":assumed-role/" in arn:
        role, _, session = arn.split(":assumed-role/", 1)[1].partition("/")
        if role.startswith("AWSServiceRole"):
            return {"kind": "service", "who": f"role {role}", "account": acct}
        if outside:
            return {"kind": "outside", "who": f"role {role} in {acct}", "account": acct}
        if role.startswith("AWSReservedSSO_"):
            return {"kind": "person", "who": f"{_sso(role)} ({session})", "account": acct}
        if re.match(r"^(i|mi)-[0-9a-f]{8,}$", session):
            return {"kind": "server", "who": f"role {role} on {session}", "account": acct}
        if "@" in session:
            return {"kind": "person", "who": f"role {role} ({session})", "account": acct}
        return {"kind": "automation", "who": f"role {role}", "account": acct}
    if t == "FederatedUser":
        return {"kind": "outside" if outside else "person", "who": arn.rsplit("/", 1)[-1], "account": acct}
    return {"kind": "outside" if outside else "automation", "who": arn or t or "unknown", "account": acct}


def _sso(role: str) -> str:
    return "permission set " + role[len("AWSReservedSSO_") :].rsplit("_", 1)[0]


def _ip_kind(ip: str) -> str:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "aws" if ip.endswith(".amazonaws.com") or ip == "AWS Internal" else ""
    return "internet" if a.is_global else "private"


def _targets(name: str, rp: dict) -> tuple[str, int, bool]:
    """(what it was aimed at, how many servers, aimed at all of them) for one event's request."""
    if name == "StartSession":
        t = str(rp.get("target") or "")
        return t, 1 if t else 0, False
    ids = rp.get("instanceIds") or []
    targets = rp.get("targets") or []
    every = any(str(v) == "*" for t in targets if isinstance(t, dict) for v in t.get("values") or [])
    if ids:
        return ", ".join(map(str, ids[:3])) + (f" and {len(ids) - 3} more" if len(ids) > 3 else ""), len(ids), every
    text = "; ".join(
        f"{t.get('key')}={','.join(map(str, t.get('values') or []))}" for t in targets if isinstance(t, dict)
    )
    return text[:120], 0, every


def _doc_owner(doc: str) -> str:
    """The account that owns a document named by ARN, or "" for a name (the account's own or AWS's)."""
    m = re.match(r"^arn:aws[\w-]*:ssm:[\w-]*:(\d{12}):document/", doc or "")
    return m.group(1) if m else ""


def read_activity(ct, account: str, org: set[str], now: datetime) -> dict:
    """The last 90 days of SSM activity in one region, from CloudTrail event history: every caller but SSM's
    own automation, with what it ran, against how many servers, and what was refused."""
    start = now - timedelta(days=DAYS)
    rows: dict[tuple, dict] = {}
    sampled: dict[str, dict] = {}
    for name, pages in PAGES.items():
        n = svc = 0
        cut = False

        def fetch(name=name, pages=pages) -> list[dict]:
            it = ct.get_paginator("lookup_events").paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}], StartTime=start,
                PaginationConfig={"PageSize": 50})  # fmt: skip
            return list(_take(it, pages))

        for i, page in enumerate(with_backoff(fetch)):
            for e in page.get("Events") or []:
                n += 1
                try:
                    ev = json.loads(e.get("CloudTrailEvent") or "{}")
                except json.JSONDecodeError:
                    continue
                who = caller(ev, account, org)
                if who["kind"] == "service":
                    svc += 1
                    continue
                rp = ev.get("requestParameters") or {}
                doc = str(rp.get("documentName") or rp.get("name") or "")
                aim, count, every = _targets(name, rp)
                shared = [str(x) for x in rp.get("accountIdsToAdd") or []]
                ip = str(ev.get("sourceIPAddress") or "")
                key = (name, who["kind"], who["who"], doc, ev.get("errorCode") or "", _ip_kind(ip))
                x = rows.setdefault(key, {"call": name, "kind": who["kind"], "who": who["who"], "from": who["account"],
                                          "doc": doc, "code": ev.get("errorCode") or "", "where": _ip_kind(ip),
                                          "ips": [], "n": 0, "servers": 0, "every": False, "aims": [],
                                          "first": "", "last": "", "shared": [], "role": ""})  # fmt: skip
                x["n"] += 1
                x["servers"] = max(x["servers"], count)
                x["every"] |= every
                if aim and aim not in x["aims"] and len(x["aims"]) < 5:
                    x["aims"].append(aim)
                if ip and ip not in x["ips"] and len(x["ips"]) < 5:
                    x["ips"].append(ip)
                for s in shared:
                    if s not in x["shared"]:
                        x["shared"].append(s)
                if name == "CreateActivation" and rp.get("iamRole"):
                    x["role"] = str(rp["iamRole"]).split("/")[-1]
                when = str(ev.get("eventTime") or "")[:19]
                x["first"] = min(x["first"] or when, when)
                x["last"] = max(x["last"], when)
            if i + 1 >= pages and page.get("NextToken"):
                cut = True
        sampled[name] = {"n": n, "service": svc, "cut": cut}
    out = sorted(rows.values(), key=lambda r: (-_weight(r, account, org), -r["n"]))
    return {"read": True, "days": DAYS, "events": sampled, "rows": out[:ROWS]}


def _take(it, pages: int):
    for i, page in enumerate(it):
        yield page
        if i + 1 >= pages:
            return


def _weight(r: dict, account: str, org: set[str]) -> int:
    return {"outside": 6, "root": 5, "key": 4, "server": 3, "automation": 1, "person": 1}.get(r["kind"], 0)


def read_securityhub(sh, account: str) -> dict:
    """Security Hub's SSM controls failing in this account and region: {public: [documents], sharing: bool}.
    None-like {"read": False} when Security Hub is off or its findings cannot be read."""
    try:
        sh.describe_hub()
    except ClientError:
        return {"read": False}
    out = {"read": True, "public": [], "sharing": False}
    filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
               "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
               "AwsAccountId": [{"Value": account, "Comparison": "EQUALS"}],
               "ComplianceSecurityControlId": [{"Value": c, "Comparison": "EQUALS"} for c in SH_CONTROLS]}  # fmt: skip
    for page in sh.get_paginator("get_findings").paginate(Filters=filters, PaginationConfig={"MaxItems": 100}):
        for f in page.get("Findings") or []:
            control = (f.get("Compliance") or {}).get("SecurityControlId") or ""
            if SH_CONTROLS.get(control) == "public":
                for res in f.get("Resources") or []:
                    name = str(res.get("Id") or "").split("/")[-1]
                    if name and name not in out["public"]:
                        out["public"].append(name)
            elif SH_CONTROLS.get(control) == "sharing":
                out["sharing"] = True
    return out


def task_region(ctx, region: str, infos: list[dict]) -> None:
    """Nodes, activity and Security Hub's SSM controls in one region, each read on its own: one refused does
    not lose the others, and is recorded as not read rather than as nothing found."""
    out: dict = {"nodes": node_summary(infos, ctx.now)}
    try:
        out["activity"] = read_activity(ctx.client("cloudtrail", region), ctx.account_id, ctx.org_ids, ctx.now)
    except (ClientError, BotoCoreError) as exc:
        out["activity"] = {"read": False, "error": _err(exc)}
    try:
        out["securityhub"] = read_securityhub(ctx.client("securityhub", region), ctx.account_id)
    except (ClientError, BotoCoreError) as exc:
        out["securityhub"] = {"read": False, "error": _err(exc)}
    ctx.r.fact("ssm_abuse", out, region)


def _err(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "") or "error"
    return type(exc).__name__


# ----------------------------------------------------------------------------- who could do it


def _like(patterns, value: str, fold: bool) -> bool:
    import fnmatch

    for p in patterns if isinstance(patterns, list) else [patterns]:
        p = str(p).replace("[", "[[]")
        if fnmatch.fnmatchcase(value.lower() if fold else value, p.lower() if fold else p):
            return True
    return False


def _covers(st: dict, action: str, resource: str) -> bool:
    if "Action" in st:
        a_ok = _like(st["Action"], action, True)
    else:
        a_ok = "NotAction" in st and not _like(st["NotAction"], action, True)
    if "Resource" in st:
        r_ok = _like(st["Resource"], resource, False)
    else:
        r_ok = "NotResource" in st and not _like(st["NotResource"], resource, False)
    return a_ok and r_ok


def _statements(doc: dict) -> list[dict]:
    st = (doc or {}).get("Statement")
    return [s for s in (st if isinstance(st, list) else [st]) if isinstance(s, dict)]


def plainly_allows(docs: list[dict], action: str, resource: str) -> bool:
    """True only when an Allow with no condition grants ``action`` on ``resource`` and no Deny (with or without
    a condition) covers it: a strict reading, so a policy narrowed by a tag or a source network is never
    reported as reaching every server."""
    allowed = False
    for doc in docs:
        for st in _statements(doc):
            if not _covers(st, action, resource):
                continue
            if st.get("Effect") == "Deny":
                return False
            if st.get("Effect") == "Allow" and not st.get("Condition"):
                allowed = True
    return allowed


def powers(docs: list[dict], boundary: dict | None, account: str, region: str) -> list[str]:
    """What the policies let an identity do to every server: run (a shell command on any EC2 instance),
    onprem (on any hybrid node), session (a shell on any instance) and params (read any parameter)."""
    inst = f"arn:aws:ec2:{region}:{account}:instance/i-0exitriskcheck0"
    node = f"arn:aws:ssm:{region}:{account}:managed-instance/mi-0exitriskcheck0"
    shell = f"arn:aws:ssm:{region}::document/AWS-RunShellScript"
    session_doc = f"arn:aws:ssm:{region}:{account}:document/SSM-SessionManagerRunShell"
    param = f"arn:aws:ssm:{region}:{account}:parameter/exitrisk-check"
    sets = [docs] + ([[boundary]] if boundary else [])

    def ok(action: str, *resources: str) -> bool:
        return all(plainly_allows(d, action, r) for d in sets for r in resources)

    out = []
    if ok("ssm:SendCommand", inst, shell):
        out.append("run")
    if ok("ssm:SendCommand", node, shell):
        out.append("onprem")
    if ok("ssm:StartSession", inst, session_doc) or ok("ssm:StartSession", node, session_doc):
        out.append("session")
    if ok("ssm:GetParameter", param) or ok("ssm:GetParametersByPath", param):
        out.append("params")
    return out


def holder_kind(role: dict, human: bool, trusted_outside: bool) -> str:
    """person, server (has an instance profile), outside (trusted by an account outside the organisation),
    function, automation."""
    if human:
        return "person"
    if role.get("InstanceProfileList"):
        return "server"
    if trusted_outside:
        return "outside"
    trust = json.dumps(role.get("AssumeRolePolicyDocument") or "")
    if "lambda.amazonaws.com" in trust:
        return "function"
    return "automation"


def read_named(label: str) -> bool:
    """A permission set or role named as read-only (Read, ReadOnly, Viewer, Audit...)."""
    return bool(READ_NAME.search(label.replace("permission set ", "").replace("role ", "")))
