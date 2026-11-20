"""SSM Abuse Review: signs that Systems Manager is being, or could be, used to take over servers.

Built from what the Cloud Assurance scan reads in each account (collectors/ssm_abuse.py and the IAM task):

* activity, last 90 days of CloudTrail event history: commands and sessions by an IAM user's key, the root
  user, an account outside the organisation or a server's own role; attempts of the same refused; documents
  shared publicly or outside the organisation; documents from outside accounts run; hybrid activations made
  by those callers; shell scripts sent to every server at once;
* exposure: servers whose own role can run commands or open a shell on every other server (one break-in then
  reaches all of them), on-premises servers whose role can, IAM users with access keys that can, roles trusted
  from outside the organisation that can, and identities named read-only that can.

Patching, Inspector and other work SSM does itself are counted and left out. Nothing is reported from a
policy narrowed by a condition, and a permissions boundary counts.
"""

from __future__ import annotations

import time

from . import riskpoints
from .collectors.ssm_abuse import SHELL_DOCS, TUNNEL_DOCS, WIDE, _doc_owner
from .filtering import AccountFilter
from .logging_config import get_logger
from .resilience import owner_of

log = get_logger("ssm_review")

RUN = ("run", "onprem", "session")
BAD_CALLERS = ("key", "root", "outside", "server")
CALLER = {
    "key": "An IAM user's access key",
    "root": "The root user",
    "outside": "An account outside the organisation",
    "server": "A server's own role",
    "person": "A person",
    "automation": "An automation role",
    "service": "AWS (patching, Inspector)",
}
CALLER_LOW = {
    "key": "an IAM user's access key",
    "root": "the root user",
    "outside": "an account outside the organisation",
    "server": "a server's own role",
}
CAN = {
    "run": "run commands on every EC2 instance",
    "onprem": "run commands on every on-premises server",
    "session": "open a shell on every server",
    "params": "read every Parameter Store value",
}
NOT_MEASURED = (
    "What each command ran: CloudTrail hides a command's parameters, and its output is kept only where Run "
    "Command sends it (S3 or CloudWatch Logs), which the scan does not read.",
    "Session Manager settings (session logging, encryption, the run-as user) and Run Command output settings: "
    "reading them needs ssm:GetDocument and ssm:GetServiceSetting, which the scan's role does not have.",
    "Which accounts each document is shared with: needs ssm:DescribeDocumentPermission. Documents made public "
    "are seen when Security Hub runs (control SSM.4), and sharing events in CloudTrail.",
    "Service control policies: a policy here may allow what the organisation's guardrails refuse.",
    "Which KMS key protects each SecureString parameter: those under a customer key also need kms:Decrypt. "
    "Under the default aws/ssm key, reading the parameter is enough.",
    "Activity older than 90 days, and more than 300 commands and 300 sessions a region (the newest are read).",
)


def build_ssm_review(scan: dict, account_filter: AccountFilter | None = None, answers=None) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    checked = (scan.get("assurance") or {}).get("accounts") or {}
    accounts = {a["id"]: a for a in scan.get("accounts") or []}
    base = {"scan_id": scan.get("id"), "not_measured": list(NOT_MEASURED), "can": CAN, "callers": CALLER, "days": 90}
    if not checked:
        return {
            **base,
            "available": False,
            "reason": "This scan has no Cloud Assurance checks: run a new scan with Cloud Assurance ticked.",
        }
    org = set(accounts) | set(checked)
    rows = []
    for aid, res in checked.items():
        meta = accounts.get(aid) or {"id": aid, "name": aid}
        if not account_filter.matches(meta.get("name", aid)):
            continue
        f = res.get("facts") or {}
        if "ssm_abuse" not in f and "ssm_holders" not in f:
            rows.append({**_who(aid, meta), "read": False})
            continue
        rows.append(_account(aid, meta, f, org))
    read = [r for r in rows if r["read"]]
    if not read:
        return {
            **base,
            "available": False,
            "reason": "This scan was made before the SSM Abuse Review existed: run a new scan with Cloud "
            "Assurance ticked (no new permissions are needed).",
        }
    riskpoints.enrich(scan, read, answers)
    for r in read:
        for x in r["reasons"]:  # something done is critical, a refusal or a power held high
            x.setdefault("severity", "critical" if x["kind"] == "activity" and not x["text"].startswith("Refused")
                         else "high")  # fmt: skip
        riskpoints.score(r, {k: sum(1 for x in r["reasons"] if x["severity"] == k) for k in riskpoints.POINTS})
        r["attention"] = (
            100 * sum(1 for x in r["reasons"] if x["kind"] == "activity")
            + 10 * sum(1 for x in r["reasons"] if x["kind"] == "exposure")
            + (1 if r["hybrid"] else 0)
        )
    read.sort(key=lambda r: (-r["attention"], -(r["ec2"] + r["hybrid"]), r["name"]))
    every = [x for r in read for x in r.pop("_activity")]
    routine = [x for x in every if _routine(x)]
    activity = sorted(
        (x for x in every if not _routine(x)),
        key=lambda x: (x["kind"] not in BAD_CALLERS, bool(x["code"]), -x["n"]),
    )
    holders = [h for r in read for h in r.pop("_holders")]
    onprem = [
        {
            k: r[k]
            for k in (
                "id",
                "name",
                "owner",
                "executive",
                "hybrid",
                "hybrid_online",
                "platforms",
                "hybrid_roles",
                "new",
                "new_count",
                "activations",
            )
        }
        for r in read
        if r["hybrid"]
    ]
    totals = {
        "accounts": len(rows),
        "read": len(read),
        "activity_read": sum(1 for r in read if r["activity_read"]),
        "ec2": sum(r["ec2"] for r in read),
        "hybrid": sum(r["hybrid"] for r in read),
        "hybrid_online": sum(r["hybrid_online"] for r in read),
        "hybrid_accounts": sum(1 for r in read if r["hybrid"]),
        "activity_accounts": sum(1 for r in read if any(x["kind"] == "activity" for x in r["reasons"])),
        "exposure_accounts": sum(1 for r in read if any(x["kind"] == "exposure" for x in r["reasons"])),
        "pivot_servers": sum(r["pivot_servers"] for r in read),
        "keys": sum(r["holders"].get("key", 0) for r in read),
        "people_commands": sum(r["people_commands"] for r in read),
        "refused": sum(r["refused"] for r in read),
        "service_commands": sum(r["service_commands"] for r in read),
    }
    log.info("ssm review: %d accounts in %.2fs", len(rows), time.perf_counter() - started)
    return {
        **base,
        "available": True,
        "totals": totals,
        "look": [r for r in read if r["reasons"]][:20],
        "accounts": read,
        "not_read": [_who(r["id"], accounts.get(r["id"]) or {}) for r in rows if not r["read"]],
        "activity": activity[:200],
        "activity_count": len(activity),
        "routine": {"lines": len(routine), "times": sum(x["n"] for x in routine)},
        "holders": sorted(holders, key=lambda h: (h["risk"] == "", h["kind"], h["account_name"], h["who"]))[:300],
        "onprem": sorted(onprem, key=lambda r: -r["hybrid"]),
    }


def _who(aid: str, meta: dict) -> dict:
    owner, executive = owner_of(meta) if meta else ("", "")
    return {"id": aid, "name": meta.get("name") or aid, "owner": owner, "executive": executive}


def _when(s: str) -> str:
    return s[:10] if s else ""


def _account(aid: str, meta: dict, f: dict, org: set[str]) -> dict:
    row = {**_who(aid, meta), "read": True}
    nodes = {"ec2": 0, "hybrid": 0, "hybrid_online": 0, "platforms": {}, "roles": {}, "new": [], "new_count": 0}
    acts, sh_public, sharing, sh_read, activity_read = [], [], False, False, False
    events = {}
    for region, x in (f.get("ssm_abuse") or {}).items():
        n = x.get("nodes") or {}
        for k in ("ec2", "hybrid", "hybrid_online", "new_count"):
            nodes[k] += int(n.get(k) or 0)
        for k in ("platforms", "roles"):
            for name, v in (n.get(k) or {}).items():
                nodes[k][name] = nodes[k].get(name, 0) + v
        nodes["new"] += [{**y, "region": region} for y in n.get("new") or []]
        a = x.get("activity") or {}
        if a.get("read"):
            activity_read = True
            for name, e in (a.get("events") or {}).items():
                t = events.setdefault(name, {"n": 0, "service": 0, "cut": False})
                t["n"] += e.get("n", 0)
                t["service"] += e.get("service", 0)
                t["cut"] |= bool(e.get("cut"))
            acts += [
                {**y, "region": region, "account": aid, "account_name": row["name"], "account_owner": row["owner"]}
                for y in a.get("rows") or []
            ]
        s = x.get("securityhub") or {}
        if s.get("read"):
            sh_read = True
            sh_public += [f"{d} ({region})" for d in s.get("public") or []]
            sharing |= bool(s.get("sharing"))
    holders = f.get("ssm_holders")
    profiles = {}  # instance profile ARN -> running instances using it
    for region, m in (f.get("instance_profiles") or {}).items():
        for inst, arn in (m or {}).items():
            profiles.setdefault(arn, []).append(f"{inst} ({region})")
    reasons: list[dict] = []
    _activity_reasons(reasons, acts, org)
    if sh_public:
        reasons.append(
            {
                "kind": "activity",
                "text": f"{_n(len(sh_public), 'SSM document')} shared publicly",
                "facts": [["Documents", ", ".join(sh_public[:10])], ["Seen by", "Security Hub control SSM.4"]],
                "means": "Anyone with an AWS account can read and run a public document: scripts, server names "
                "and any secret written into them are open to the world.",
                "do": "Make the documents private, and turn on Block public sharing for SSM documents in every region.",
            }
        )
    pivot = _exposure_reasons(reasons, holders, profiles, nodes)
    by_kind: dict[str, int] = {}
    params_only = 0
    out_holders = []
    for h in holders or []:
        runs = [c for c in h["can"] if c in RUN]
        if not runs:
            params_only += 1
            continue
        by_kind[h["kind"]] = by_kind.get(h["kind"], 0) + 1
        servers = [i for p in h.get("profiles") or [] for i in profiles.get(p, [])]
        risk = ""
        if h["kind"] == "server" and servers:
            risk = f"on {_n(len(servers), 'running server')}"
        elif h["kind"] == "key":
            risk = "an access key"
        elif h.get("outside"):
            risk = "trusted from outside the organisation"
        elif h.get("read_named"):
            risk = "named read-only"
        elif h["role"] in nodes["roles"]:
            risk = f"on {_n(nodes['roles'][h['role']], 'on-premises server')}"
        out_holders.append(
            {
                **{k: h.get(k) for k in ("who", "kind", "can", "admin")},
                "risk": risk,
                "servers": servers[:5],
                "server_count": len(servers),
                "account": aid,
                "account_name": row["name"],
                "account_owner": row["owner"],
            }
        )
    people = [a for a in acts if a["kind"] == "person" and not a["code"]]
    row.update(
        {
            "ec2": nodes["ec2"],
            "hybrid": nodes["hybrid"],
            "hybrid_online": nodes["hybrid_online"],
            "platforms": nodes["platforms"],
            "hybrid_roles": [
                {"role": r, "nodes": n, "can": next((h["can"] for h in holders or [] if h["role"] == r), [])}
                for r, n in sorted(nodes["roles"].items(), key=lambda kv: -kv[1])
            ],
            "new": sorted(nodes["new"], key=lambda y: y["at"], reverse=True)[:10],
            "new_count": nodes["new_count"],
            "activations": [
                {"who": a["who"], "kind": a["kind"], "n": a["n"], "last": _when(a["last"]), "role": a["role"]}
                for a in acts
                if a["call"] == "CreateActivation" and not a["code"]
            ],
            "holders_read": holders is not None,
            "holders": by_kind,
            "params_only": params_only,
            "activity_read": activity_read,
            "events": events,
            "people_commands": sum(a["n"] for a in people if a["call"] == "SendCommand"),
            "people_sessions": sum(a["n"] for a in people if a["call"] == "StartSession"),
            "service_commands": sum(e["service"] for e in events.values()),
            "refused": sum(
                a["n"] for a in acts if a["code"] in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")
            ),
            "last": max((a["last"] for a in acts), default="")[:10],
            "sh_read": sh_read,
            "sharing_open": sharing,
            "pivot_servers": pivot,
            "reasons": reasons,
            "_activity": acts,
            "_holders": out_holders,
        }
    )
    return row


def _n(n: int, what: str) -> str:
    return f"{n:,} {what}{'' if n == 1 else 's'}"


def _ran(a: dict) -> str:
    if a["doc"] in TUNNEL_DOCS:
        return "tunnelled through a server to another host"
    return "opened a shell on a server" if a["call"] == "StartSession" else "ran commands on servers"


def _routine(a: dict) -> bool:
    """A person's or an automation role's command or session that worked and reached a few servers: everyday
    operations, counted per account rather than listed."""
    return (a["kind"] in ("person", "automation", "function") and not a["code"]
            and a["call"] in ("SendCommand", "StartSession") and not a["every"] and a["servers"] < WIDE
            and a["doc"] not in TUNNEL_DOCS)  # fmt: skip


def _act_facts(a: dict) -> list[list[str]]:
    facts = [
        ["Who", a["who"]],
        ["Caller", CALLER.get(a["kind"], a["kind"])],
        ["Call", a["call"]],
        ["Times", f"{a['n']:,}"],
        ["When", f"{_when(a['first'])} to {_when(a['last'])}" if a["first"] != a["last"] else _when(a["last"])],
        ["Region", a["region"]],
    ]
    if a["doc"]:
        facts.append(["Document", a["doc"]])
    if a["aims"]:
        facts.append(["Aimed at", "; ".join(a["aims"]) + (" (every server)" if a["every"] else "")])
    if a["ips"]:
        facts.append(
            [
                "From",
                ", ".join(a["ips"]) + {"internet": " (internet)", "private": " (private network)"}.get(a["where"], ""),
            ]
        )
    if a["code"]:
        facts.append(["Refused with", a["code"]])
    if a["from"] and a["from"] != a["account"]:
        facts.append(["Caller's account", a["from"]])
    return facts


def _activity_reasons(reasons: list[dict], acts: list[dict], org: set[str]) -> None:
    for a in acts:
        call, ok = a["call"], not a["code"]
        if call in ("SendCommand", "StartSession") and a["kind"] in BAD_CALLERS:
            what = CALLER[a["kind"]]
            if ok:
                text = f"{what} {_ran(a)}: {a['who']}, {_n(a['n'], 'time')}, last {_when(a['last'])}"
                means = {
                    "key": "A long-lived access key can be copied off a laptop or out of a repository and used from "
                    "anywhere. With SSM it runs code as root or SYSTEM on the servers, with no SSH, no open port "
                    "and nothing for the network to stop.",
                    "root": "The root user should never be used for day-to-day work; a command from it is either an "
                    "emergency or someone who has the root password.",
                    "outside": "An identity from an account outside the organisation drove SSM in this account: a "
                    "vendor, or someone who should not have access.",
                    "server": "A server used its own role to command other servers. That is how one break-in spreads: "
                    "the attacker on one host takes the rest through SSM.",
                }[a["kind"]]
                do = (
                    "Confirm who this was and that it was expected. If not, treat the servers named as compromised: "
                    "revoke the credentials, read the command output and session logs, and look at what changed "
                    "on them."
                )
            else:
                text = f"Refused: {CALLER_LOW[a['kind']]} tried to use SSM on servers: {a['who']}, {_n(a['n'], 'time')}"
                means = (
                    "The identity is not allowed, so nothing ran, but something holding these credentials "
                    "tried. Stolen credentials are often tried against SSM first."
                )
                do = "Find what used these credentials, and why. Rotate them if no one can say."
            reasons.append({"kind": "activity", "text": text, "facts": _act_facts(a), "means": means, "do": do})
        elif call == "ModifyDocumentPermission" and ok and a["shared"]:
            public = any(s.lower() == "all" for s in a["shared"])
            outside = [s for s in a["shared"] if s.lower() != "all" and s not in org]
            if public or outside:
                reasons.append(
                    {
                        "kind": "activity",
                        "text": f"Document {a['doc']} shared "
                        f"{'publicly' if public else 'with ' + ', '.join(outside[:3])} by {a['who']}",
                        "facts": _act_facts(a) + [["Shared with", ", ".join(a["shared"][:10])]],
                        "means": "A shared document can be read and run from the other account: the script, "
                        "the server names and anything written into it.",
                        "do": "Remove the sharing unless it is meant, and turn on Block public sharing.",
                    }
                )
        elif call == "SendCommand" and ok and _doc_owner(a["doc"]) and _doc_owner(a["doc"]) not in org:
            reasons.append(
                {
                    "kind": "activity",
                    "text": f"Ran a document owned by account {_doc_owner(a['doc'])}, "
                    f"outside the organisation: {a['who']}",
                    "facts": _act_facts(a),
                    "means": "Whoever owns that account decides what the document does, and can change it.",
                    "do": "Copy the document into your own account, review it, and run that instead.",
                }
            )
        elif call == "CreateActivation" and ok and a["kind"] in BAD_CALLERS:
            reasons.append(
                {
                    "kind": "activity",
                    "text": f"{CALLER[a['kind']]} created a hybrid activation: {a['who']}",
                    "facts": _act_facts(a) + ([["Role given", a["role"]]] if a["role"] else []),
                    "means": "An activation lets any machine join this account as a managed server. "
                    "Attackers register their own machine to keep a way in.",
                    "do": "Check the activation and the nodes it registered; delete any not expected.",
                }
            )
        elif (
            call == "SendCommand"
            and ok
            and a["kind"] in ("person", "automation")
            and (a["every"] or a["servers"] >= WIDE)
            and (a["doc"] in SHELL_DOCS)
        ):
            reasons.append(
                {
                    "kind": "activity",
                    "text": f"A shell script sent to {'every server' if a['every'] else _n(a['servers'], 'server')} "
                    f"at once by {a['who']}",
                    "facts": _act_facts(a),
                    "means": "One command reached many servers. It may be routine; it is also exactly how "
                    "ransomware is pushed through SSM.",
                    "do": "Confirm the change it belonged to. Use State Manager or a maintenance window with "
                    "a reviewed document for fleet-wide work.",
                }
            )
        elif call == "StartSession" and ok and a["doc"] in TUNNEL_DOCS and a["kind"] in BAD_CALLERS:
            reasons.append(
                {
                    "kind": "activity",
                    "text": f"A tunnel through a server to another host: {a['who']}",
                    "facts": _act_facts(a),
                    "means": "Port forwarding to a remote host goes around security groups and the network's "
                    "own controls.",
                    "do": "Confirm it was expected, and limit AWS-StartPortForwardingSessionToRemoteHost to "
                    "the people who need it.",
                }
            )


def _exposure_reasons(reasons: list[dict], holders: list | None, profiles: dict, nodes: dict) -> int:
    """Who could take every server, from the policies. Returns how many running servers hold such a role."""
    if holders is None:
        return 0
    pivot = 0
    for h in holders:
        runs = [c for c in h["can"] if c in RUN]
        if not runs:
            continue
        can = " and ".join(CAN[c] for c in runs)
        servers = [i for p in h.get("profiles") or [] for i in profiles.get(p, [])]
        facts = [["Identity", h["who"]], ["Can", can], ["Administrator", "yes" if h.get("admin") else "no"]]
        if h["kind"] == "server" and servers:
            pivot += len(servers)
            reasons.append(
                {
                    "kind": "exposure",
                    "text": f"{_n(len(servers), 'running server')} can {can} ({h['who']})",
                    "facts": facts
                    + [
                        [
                            "Servers holding it",
                            ", ".join(servers[:8]) + (f" and {len(servers) - 8} more" if len(servers) > 8 else ""),
                        ]
                    ],
                    "means": "Break into one of these servers and its own role takes the others through SSM, "
                    "as root or SYSTEM, without touching the network.",
                    "do": "Take ssm:SendCommand and ssm:StartSession off the server's role (AmazonSSMFullAccess "
                    "is the usual cause); servers need only AmazonSSMManagedInstanceCore. If the server is a "
                    "pipeline runner that must deploy, limit it to the servers it deploys to, by tag.",
                }
            )
        elif h["role"] in nodes["roles"]:
            n = nodes["roles"][h["role"]]
            reasons.append(
                {
                    "kind": "exposure",
                    "text": f"{_n(n, 'on-premises server')} use role {h['role']}, which can {can}",
                    "facts": facts + [["On-premises servers using it", f"{n:,}"]],
                    "means": "A break-in on one server in the data centre takes every server SSM manages, in "
                    "AWS and on premises.",
                    "do": "Give hybrid nodes a role with AmazonSSMManagedInstanceCore only.",
                }
            )
        elif h["kind"] == "key":
            reasons.append(
                {
                    "kind": "exposure",
                    "text": f"{h['who']} has an access key and can {can}",
                    "facts": facts,
                    "means": "A long-lived key that leaks (a laptop, a repository, a CI log) is a remote shell "
                    "on every server, from anywhere.",
                    "do": "Move the work to a role. If a key must stay, limit its SSM rights to named servers "
                    "and a source network.",
                }
            )
        elif h.get("outside") and not h.get("admin"):
            reasons.append(
                {
                    "kind": "exposure",
                    "text": f"{h['who']} is trusted from outside the organisation and can {can}",
                    "facts": facts,
                    "means": "Whoever controls the other account can run code on these servers.",
                    "do": "Confirm the vendor needs it; limit the role to named servers, or remove SSM from it.",
                }
            )
        elif h.get("read_named"):
            reasons.append(
                {
                    "kind": "exposure",
                    "text": f"{h['who']} is named read-only but can {can}",
                    "facts": facts,
                    "means": "People given a read-only role do not expect it to run code on servers, and "
                    "neither do the people who approve it.",
                    "do": "Remove ssm:SendCommand and ssm:StartSession from it, or rename it for what it is.",
                }
            )
    return pivot
