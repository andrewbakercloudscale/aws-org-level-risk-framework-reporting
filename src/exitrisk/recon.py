"""Who is probing each account: the signs of reconnaissance in a scan's failed traffic.

Read from the facts the account map reads too: rejected flow-log rows (access_flows) and API calls refused in
CloudTrail (trail_denials, usually the management account's organisation trail). Only clear patterns count,
so a stray rejected packet or one mistyped password never marks an account:

* network: an internet address refused on SWEEP or more ports or internal addresses (a scan), or refused in
  two or more scanned accounts (someone mapping the organisation);
* AWS: one caller refused on ENUM or more different API calls (listing what a credential can do), or LOGINS or
  more failed console sign-ins.
"""

from __future__ import annotations

import ipaddress

SWEEP = 5
ENUM = 10
LOGINS = 5
SHOWN = 3


def _global(a) -> bool:
    try:
        return ipaddress.ip_address(a).is_global
    except (ValueError, TypeError):
        return False


def account_probes(checked: dict) -> dict[str, dict]:
    """{account id: {network: [signs], api: [signs]}} for the accounts with a clear sign of reconnaissance.
    `checked` is the scan's assurance accounts ({id: {facts: ...}})."""
    per: dict[str, dict[str, dict]] = {}
    seen_in: dict[str, set[str]] = {}
    for aid, raw in checked.items():
        for fl in ((raw.get("facts") or {}).get("access_flows") or {}).values():
            for r in fl.get("rejected") or []:
                src, dst = r.get("src"), r.get("dst")
                if not _global(src) or _global(dst):
                    continue
                x = per.setdefault(aid, {}).setdefault(src, {"ports": set(), "targets": set(), "attempts": 0})
                if r.get("port"):
                    x["ports"].add(str(r["port"]))
                if dst:
                    x["targets"].add(dst)
                x["attempts"] += r.get("flows") or 0
                seen_in.setdefault(src, set()).add(aid)
    out: dict[str, dict] = {}
    for aid, ips in per.items():
        signs = []
        for ip, x in sorted(ips.items(), key=lambda kv: -kv[1]["attempts"]):
            others = len(seen_in[ip]) - 1
            if len(x["ports"]) >= SWEEP or len(x["targets"]) >= SWEEP or others:
                elsewhere = f"also refused in {others} other account{'s' if others != 1 else ''}"
                what = [f"{len(x['ports'])} ports" if len(x["ports"]) >= SWEEP else "",
                        f"{len(x['targets'])} addresses" if len(x["targets"]) >= SWEEP else "",
                        elsewhere if others else ""]  # fmt: skip
                signs.append(f"{ip} refused at the network: {', '.join(w for w in what if w)}")
        if signs:
            out.setdefault(aid, {"network": [], "api": []})["network"] = signs
    callers: dict[tuple, dict] = {}
    for raw in checked.values():
        for r in ((raw.get("facts") or {}).get("trail_denials") or {}).get("rows") or []:
            if not r.get("account"):
                continue
            c = callers.setdefault((r["account"], r.get("who") or "", r.get("ip") or ""), {"calls": set(), "logins": 0})
            if r.get("call") == "ConsoleLogin":
                c["logins"] += r.get("n") or 0
            else:
                c["calls"].add(f"{r.get('svc')}:{r.get('call')}")
    for (aid, who, ip), c in sorted(callers.items(), key=lambda kv: (-len(kv[1]["calls"]), -kv[1]["logins"])):
        name = (who.rsplit("/", 1)[-1] or who or "unknown caller") + (f" from {ip}" if ip else "")
        signs = []
        if len(c["calls"]) >= ENUM:
            signs.append(f"{name} refused on {len(c['calls'])} different API calls")
        if c["logins"] >= LOGINS:
            signs.append(f"{c['logins']} failed console sign-ins by {name}")
        if signs:
            out.setdefault(aid, {"network": [], "api": []})["api"] += signs
    for x in out.values():
        x["network"], x["api"] = x["network"][:SHOWN], x["api"][:SHOWN]
    return out
