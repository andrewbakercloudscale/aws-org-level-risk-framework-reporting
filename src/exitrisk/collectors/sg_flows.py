"""The AWS reads behind the Security Group Review: one account, live, read-only.

Per region:

* ``snapshot``: the security groups and their inbound rules (prefix lists resolved), every network interface
  with its addresses and groups, the VPCs, network ACLs, VPN static routes and the flow logs;
* ``rule_history``: inbound rule changes from CloudTrail event history (90 days), so the rules in force on any
  day can be worked out backwards from today's;
* ``detail_query`` and ``public_query``: the two Logs Insights queries run over each slice of time. The detail
  query keeps every accepted inbound connection, and every refused one from a private address, by source,
  target address, interface, protocol and port; the public query keeps each refused internet source in one
  row (scanners would otherwise fill the result).

Every call is in the scan's member role already: ec2 Describe*, ec2:GetManagedPrefixListEntries,
cloudtrail:LookupEvents, logs:StartQuery, logs:GetQueryResults and logs:StopQuery.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG, with_backoff
from ..logging_config import get_logger
from .access import DEFAULT_FORMAT, eni_kind, vpc_cidrs

log = get_logger("sg_flows")

ROWS = 10000  # the most rows one Logs Insights query returns
EPHEMERAL = 32768  # ports from here up are folded into one: replies to the account's own connections land there
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
NEEDED = ("srcaddr", "dstaddr", "dstport", "protocol", "action", "interface_id")
HISTORY_DAYS = 90
HISTORY_EVENTS = ("AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "ModifySecurityGroupRules")
HISTORY_PAGES = 20  # 50 events a page, per event name and region
VPC_FILTER_MAX = 40  # more VPC ranges than this and the inbound filter is left to the report


def _pages(client, op: str, key: str, **kw) -> list:
    out = []
    pager = client.get_paginator(op)
    for page in with_backoff(lambda: list(pager.paginate(**kw))):
        out += page.get(key) or []
    return out


def _name(tags) -> str:
    return next((t.get("Value", "") for t in tags or [] if t.get("Key") == "Name"), "")


def fields_of(log_format: str | None) -> list[str]:
    return [f.strip("${}").replace("-", "_") for f in (log_format or DEFAULT_FORMAT).split()]


def readable(log_format: str | None) -> bool:
    return set(NEEDED) <= set(fields_of(log_format))


def _private(field: str) -> str:
    return "(" + " or ".join(f'isIpv4InSubnet({field}, "{c}")' for c in PRIVATE_V4) + ")"


def _base(log_format: str | None, vpc_ranges: list[str]) -> tuple[str, str, str, bool] | None:
    """The parse and the inbound filter for a format: (query head, source field, target field, filtered by
    direction). Inbound is the flow-direction field when the format has it, else a target inside the
    account's VPCs (the report drops the interface's own outbound records)."""
    fields = fields_of(log_format)
    if not set(NEEDED) <= set(fields):
        return None
    src = "f_pkt_srcaddr" if "pkt_srcaddr" in fields else "f_srcaddr"
    dst = "f_pkt_dstaddr" if "pkt_dstaddr" in fields else "f_dstaddr"
    head = f'parse @message "{" ".join("*" for _ in fields)}" as {", ".join("f_" + f for f in fields)}'
    head += f' | filter {src} != "-" and {dst} != "-"'
    by_dir = "flow_direction" in fields
    if by_dir:
        head += ' and f_flow_direction = "ingress"'
    elif vpc_ranges and len(vpc_ranges) <= VPC_FILTER_MAX:
        head += " and (" + " or ".join(f'isIpv4InSubnet({dst}, "{c}")' for c in vpc_ranges) + ")"
    return head, src, dst, by_dir


def detail_query(log_format: str | None, vpc_ranges: list[str], fold: bool = True) -> str | None:
    """Accepted inbound connections, and refused ones from private addresses, by source, target, interface,
    protocol, port (ports from EPHEMERAL up folded into one when ``fold``) and action."""
    b = _base(log_format, vpc_ranges)
    if not b:
        return None
    head, src, dst, _ = b
    port = f"least(f_dstport, {EPHEMERAL})" if fold else "f_dstport"
    return (
        f'{head} and (f_action = "ACCEPT" or {_private(src)})'
        f" | fields {port} as dport"
        f" | stats count(*) as flows, sum(f_bytes) as bytes by {src} as src, {dst} as dst,"
        f" f_interface_id as eni, f_protocol as proto, dport, f_action as action | limit {ROWS}"
    )


def public_query(log_format: str | None, vpc_ranges: list[str]) -> str | None:
    """Refused inbound connections from internet addresses, one row per source: how many, on how many ports
    and targets, and the last target, interface, port and protocol (exact when there was only one)."""
    b = _base(log_format, vpc_ranges)
    if not b:
        return None
    head, src, dst, _ = b
    return (
        f'{head} and f_action = "REJECT" and not {_private(src)}'
        f" | stats count(*) as flows, count_distinct(f_dstport) as ports, count_distinct({dst}) as dsts,"
        f" latest({dst}) as dst, latest(f_interface_id) as eni, latest(f_dstport) as port,"
        f" latest(f_protocol) as proto by {src} as src | sort flows desc | limit {ROWS}"
    )


def run_query(logs, groups: list[str], query: str, start: int, end: int, wait: float = 900,
              cancelled=lambda: False) -> tuple[list[dict] | None, int, str]:  # fmt: skip
    """(rows or None, bytes scanned, status) of one Logs Insights query over [start, end)."""
    qid = with_backoff(
        lambda: logs.start_query(
            logGroupNames=groups[:50], startTime=int(start), endTime=int(end) - 1, queryString=query, limit=ROWS
        )  # fmt: skip
    )["queryId"]
    waited, pause = 0.0, 1.0
    while waited < wait and not cancelled():
        res = with_backoff(lambda: logs.get_query_results(queryId=qid))
        status = res.get("status")
        scanned = int(float((res.get("statistics") or {}).get("bytesScanned") or 0))
        if status == "Complete":
            return [{c["field"]: c.get("value") for c in row} for row in res.get("results") or []], scanned, status
        if status in ("Failed", "Cancelled", "Timeout", "Unknown"):
            return None, scanned, status
        time.sleep(pause)
        waited += pause
        pause = min(pause * 1.5, 10)
    try:
        logs.stop_query(queryId=qid)
    except (ClientError, BotoCoreError) as exc:
        log.debug("could not stop query %s: %s", qid, exc)
    return None, 0, "Cancelled" if cancelled() else "Timeout"


# ------------------------------------------------------------------------------------------- snapshot
def _rule(perm: dict) -> dict:
    proto = str(perm.get("IpProtocol", "-1"))
    proto = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58"}.get(proto, proto)
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if proto == "-1" or lo in (None, -1):
        lo, hi = 0, 65535
    return {
        "proto": proto,
        "from": int(lo),
        "to": int(hi if hi not in (None, -1) else 65535),
        "cidrs": [r["CidrIp"] for r in perm.get("IpRanges") or [] if r.get("CidrIp")],
        "descs": {r["CidrIp"]: r["Description"] for r in perm.get("IpRanges") or [] if r.get("Description")},
        "pls": [p["PrefixListId"] for p in perm.get("PrefixListIds") or [] if p.get("PrefixListId")],
        "refs": [p.get("GroupId", "") for p in perm.get("UserIdGroupPairs") or []],
        "any6": any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges") or []),
    }


def snapshot(session, region: str) -> dict:
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    out: dict = {"errors": []}
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    out["vpcs"] = [{"id": v["VpcId"], "name": _name(v.get("Tags")), "cidrs": vpc_cidrs([v])} for v in vpcs]
    out["groups"] = {
        g["GroupId"]: {
            "name": g.get("GroupName", ""),
            "vpc": g.get("VpcId", ""),
            "tag": _name(g.get("Tags")),
            "rules": [_rule(p) for p in g.get("IpPermissions") or []],
        }  # fmt: skip
        for g in _pages(ec2, "describe_security_groups", "SecurityGroups")
    }
    enis = {}
    for e in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces"):
        ips = [a["PrivateIpAddress"] for a in e.get("PrivateIpAddresses") or [] if a.get("PrivateIpAddress")]
        enis[e["NetworkInterfaceId"]] = {
            "ips": ips,
            "prefixes": [p["Ipv4Prefix"] for p in e.get("Ipv4Prefixes") or [] if p.get("Ipv4Prefix")],
            "groups": [g["GroupId"] for g in e.get("Groups") or []],
            "subnet": e.get("SubnetId", ""),
            "vpc": e.get("VpcId", ""),
            "kind": eni_kind(e),
            "desc": (e.get("Description") or "")[:80],
            "instance": (e.get("Attachment") or {}).get("InstanceId", ""),
            "public": (e.get("Association") or {}).get("PublicIp", ""),
        }
    out["enis"] = enis
    pls: dict = {}
    for pid in sorted({p for g in out["groups"].values() for r in g["rules"] for p in r["pls"]}):
        try:
            pls[pid] = [x["Cidr"] for x in _pages(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pid)
                        if x.get("Cidr") and ":" not in x["Cidr"]]  # fmt: skip
        except (ClientError, BotoCoreError) as exc:
            out["errors"].append(f"prefix list {pid}: {exc}")
    out["prefix_lists"] = pls
    nacls = {}
    for n in _pages(ec2, "describe_network_acls", "NetworkAcls"):
        entries = sorted(
            (
                {"n": x.get("RuleNumber", 32767), "proto": str(x.get("Protocol", "-1")),
                 "allow": x.get("RuleAction") == "allow", "cidr": x.get("CidrBlock", ""),
                 "from": (x.get("PortRange") or {}).get("From", 0),
                 "to": (x.get("PortRange") or {}).get("To", 65535)}
                for x in n.get("Entries") or [] if not x.get("Egress") and x.get("CidrBlock")
            ),
            key=lambda x: x["n"],
        )  # fmt: skip
        for a in n.get("Associations") or []:
            nacls[a.get("SubnetId", "")] = {"id": n.get("NetworkAclId", ""), "entries": entries}
    out["nacls"] = nacls
    try:
        out["vpns"] = [{"name": _name(v.get("Tags")) or v["VpnConnectionId"],
                        "routes": [r["DestinationCidrBlock"] for r in v.get("Routes") or []
                                   if r.get("DestinationCidrBlock")]}
                       for v in with_backoff(lambda: ec2.describe_vpn_connections())["VpnConnections"]
                       if v.get("State") != "deleted"]  # fmt: skip
    except (ClientError, BotoCoreError) as exc:
        out["vpns"] = []
        out["errors"].append(f"VPN connections: {exc}")
    out["flow_logs"] = [
        {"id": f.get("FlowLogId", ""), "resource": f.get("ResourceId", ""), "traffic": f.get("TrafficType", ""),
         "dest": f.get("LogDestinationType", "cloud-watch-logs"), "group": f.get("LogGroupName", ""),
         "format": f.get("LogFormat") or DEFAULT_FORMAT, "status": f.get("FlowLogStatus", ""),
         "created": f["CreationTime"].timestamp() if hasattr(f.get("CreationTime"), "timestamp") else None}
        for f in _pages(ec2, "describe_flow_logs", "FlowLogs")
    ]  # fmt: skip
    return out


# -------------------------------------------------------------------------------------------- history
def _items(x) -> list:
    if isinstance(x, dict):
        return x.get("items") or []
    return x or []


def _perm_entries(perms) -> list[list]:
    """[proto, from, to, source] for each IPv4 range and prefix list in CloudTrail's ipPermissions."""
    out = []
    for p in _items(perms):
        r = _rule({"IpProtocol": p.get("ipProtocol"), "FromPort": p.get("fromPort"), "ToPort": p.get("toPort")})
        for x in _items(p.get("ipRanges")):
            if x.get("cidrIp"):
                out.append([r["proto"], r["from"], r["to"], x["cidrIp"]])
        for x in _items(p.get("prefixListIds")):
            if x.get("prefixListId"):
                out.append([r["proto"], r["from"], r["to"], x["prefixListId"]])
    return out


def parse_event(ev: dict) -> dict | None:
    """One CloudTrail record as {t, group, added, removed, unknown, who, name}; None for a failed call."""
    try:
        doc = json.loads(ev.get("CloudTrailEvent") or "{}")
    except ValueError:
        return None
    if doc.get("errorCode"):
        return None
    name = doc.get("eventName") or ev.get("EventName", "")
    req = doc.get("requestParameters") or {}
    t = ev.get("EventTime")
    t = t.timestamp() if hasattr(t, "timestamp") else None
    if t is None:
        try:
            t = datetime.fromisoformat(doc.get("eventTime", "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    ident = doc.get("userIdentity") or {}
    who = (ident.get("arn") or ident.get("principalId") or "").split("/")[-1][:80]
    out = {"t": t, "name": name, "who": who, "added": [], "removed": [], "unknown": False}
    if name == "ModifySecurityGroupRules":
        inner = req.get("ModifySecurityGroupRulesRequest") or req
        out["group"] = inner.get("GroupId") or inner.get("groupId") or ""
        out["unknown"] = True  # the rule's earlier value is not in the event
        return out
    out["group"] = req.get("groupId") or ""
    entries = _perm_entries(req.get("ipPermissions"))
    if name == "RevokeSecurityGroupIngress" and _items(req.get("securityGroupRuleIds")) and not entries:
        out["unknown"] = True  # revoked by rule id: which range it was is not in the event
    out["added" if name == "AuthorizeSecurityGroupIngress" else "removed"] = entries
    return out if out["group"] else None


def rule_history(session, region: str, now: datetime, days: int = HISTORY_DAYS) -> dict:
    """Inbound rule changes in ``region``, oldest first, and from when the list is whole."""
    ct = session.client("cloudtrail", region_name=region, config=BOTO_CONFIG)
    since = now - timedelta(days=days)
    events, whole_since = [], since.timestamp()
    for name in HISTORY_EVENTS:
        token, pages = None, 0
        while True:
            kw = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": name}], "StartTime": since,
                  "EndTime": now, "MaxResults": 50}  # fmt: skip
            if token:
                kw["NextToken"] = token
            page = with_backoff(lambda kw=kw: ct.lookup_events(**kw))
            for ev in page.get("Events") or []:
                parsed = parse_event(ev)
                if parsed:
                    events.append(parsed)
            token, pages = page.get("NextToken"), pages + 1
            if not token:
                break
            if pages >= HISTORY_PAGES:  # too many to read: the history is whole only back to the oldest read
                oldest = min((e["t"] for e in events if e["name"] == name), default=now.timestamp())
                whole_since = max(whole_since, oldest)
                break
    events.sort(key=lambda e: e["t"])
    return {"events": events, "whole_since": whole_since, "read": True}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
