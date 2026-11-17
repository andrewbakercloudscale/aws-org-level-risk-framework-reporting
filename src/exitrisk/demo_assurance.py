"""Synthetic Cloud Assurance Framework results for the demo organisation (screenshots and tests).

Every rule the scan measures gets a plausible state per account: production accounts are cleaner
than sandboxes, payments accounts hold sensitive buckets, a few accounts carry the classic findings
(SSH open to the internet, a public bucket, root without MFA). Deterministic for a given seed.
"""

from __future__ import annotations

import random

from .collectors.assurance import GLOBAL_TASKS, REGION_TASKS, catalog

# Chance a rule fails, by severity, before the account's own adjustment.
_FAIL = {"critical": 0.02, "high": 0.07, "medium": 0.12, "low": 0.2}
_PEOPLE = ["Alex Morgan", "Priya Shah", "Sam Patel", "Lerato Mokoena", "Jordan Lee", "Thabo Dlamini", "Chris Ndlovu",
           "Emma Botha", "Kim Naidoo", "Ravi Pillay", "Megan Smit", "Sipho Khumalo", "Dana Fourie"]  # fmt: skip
# Findings that make the demo tell a story: (account name part, rule, evidence).
_STORY = [
    ("legacy", "admin_ports_public", ["22 open on i-0a1b2c3d4e5f60718 via sg-0123abcd (eu-west-1)"]),
    ("marketing", "s3_public_bucket", ["campaign-assets-public"]),
    ("sandbox", "root_mfa", ["root user"]),
    ("data-platform", "rds_single_az", ["reporting-db (eu-west-1)"]),
    ("payments", "sensitive_bucket", []),
    # an attack chain in a probed account: a way in, a way to spread, and the settlement files to take
    ("payments-core", "db_ports_public", ["5432 open on payments-ledger-db via sg-0f1e2d3c (eu-west-1)"]),
    ("payments-core", "workload_admin", ["role payments-batch-runner (AdministratorAccess)"]),
]


# Findings the demo's Security Hub and Inspector rules report: (id, title, package, fixed in, CVSS, EPSS, exploit).
_VULNS = [
    ("CVE-2021-44228", "CVE-2021-44228 - org.apache.logging.log4j:log4j-core", "log4j-core 2.14.1", "2.17.1", 10.0,
     0.94, True),
    ("CVE-2023-44487", "CVE-2023-44487 - golang.org/x/net", "golang.org/x/net 0.15.0", "0.17.0", 7.5, 0.82, True),
    ("CVE-2024-3094", "CVE-2024-3094 - xz-utils", "xz-utils 5.6.0", "5.6.2", 10.0, 0.6, True),
    ("CVE-2022-22965", "CVE-2022-22965 - org.springframework:spring-beans", "spring-beans 5.3.17", "5.3.18", 9.8,
     0.97, True),
    ("CVE-2024-6387", "CVE-2024-6387 - openssh", "openssh 9.6p1", "9.8p1", 8.1, 0.4, False),
    ("CVE-2023-38545", "CVE-2023-38545 - curl", "curl 8.3.0", "8.4.0", 9.8, 0.2, False),
    ("CVE-2024-45337", "CVE-2024-45337 - golang.org/x/crypto", "golang.org/x/crypto 0.30.0", "0.31.0", 9.1, 0.05,
     False),
    ("CVE-2023-4863", "CVE-2023-4863 - libwebp", "libwebp 1.3.1", "1.3.2", 8.8, 0.3, True),
]  # fmt: skip
_CONTROLS = [
    ("S3.1", "S3 general purpose buckets should have block public access settings enabled"),
    ("IAM.6", "Hardware MFA should be enabled for the root user"),
    ("EC2.19", "Security groups should not allow unrestricted access to ports with high risk"),
    ("SSM.7", "SSM documents should have the block public sharing setting enabled"),
    ("RDS.2", "RDS DB instances should prohibit public access"),
]


def _finding_facts(checks: dict, rng: random.Random) -> dict:
    """Detail behind the failing Security Hub and Inspector rules, for the top findings tables."""
    out: dict[str, dict] = {}
    rule_sev = {"sh_critical_findings": ("securityhub", "critical"), "sh_high_aged": ("securityhub", "high"),
                "vuln_critical": ("inspector", "critical"), "vuln_high_aged": ("inspector", "high")}  # fmt: skip
    for cid, (source, sev) in rule_sev.items():
        if checks.get(cid, {}).get("status") != "fail":
            continue
        rows = []
        for v in rng.sample(_VULNS, rng.randint(2, 4)):
            vid, title, pkg, fixed, cvss, epss, exploit = v
            rows.append({"title": title, "sev": sev, "id": vid, "kind": "vulnerability",
                         "product": "Inspector", "res": [f"i-0{rng.randint(10**15, 10**16 - 1):x}"[:19]],
                         "rtype": "AwsEc2Instance", "age": rng.randint(3, 200), "cvss": cvss, "epss": epss,
                         "exploit": exploit, "fix": fixed, "pkg": pkg, "url": "",
                         "n": rng.choice([1, 1, 2, 4, 9])})  # fmt: skip
        if source == "securityhub":
            for ctl, title in rng.sample(_CONTROLS, 2):
                rows.append({"title": f"{ctl} {title}", "sev": sev, "id": ctl, "kind": "control",
                             "product": "Security Hub", "res": [], "rtype": "", "age": rng.randint(10, 400),
                             "cvss": None, "epss": None, "exploit": None, "fix": "", "pkg": "", "url": "",
                             "n": rng.choice([1, 2, 3])})  # fmt: skip
        checks[cid]["ev"] = [f"{x['title']} (eu-west-1)" for x in rows]
        checks[cid]["n"] = sum(x["n"] for x in rows)
        out.setdefault(f"{source}_findings", {"eu-west-1": []})["eu-west-1"].extend(rows)
    return out


def _evidence(cid: str, region: str, rng: random.Random) -> list[str]:
    n = rng.choice([1, 1, 1, 2, 3, 5, 8])
    return [f"{cid.replace('_', '-')}-{rng.randint(100, 999)} ({region})" for _ in range(n)]


def build(accounts: list[dict], seed: int = 11) -> dict:
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security
    rules = {c["id"]: c for c in catalog()["checks"]}
    measured = list(dict.fromkeys(c for t in GLOBAL_TASKS + REGION_TASKS for c in t[1]))
    out: dict[str, dict] = {}
    for acct in accounts:
        if acct.get("status") != "ACTIVE":
            continue
        name = acct["name"]
        if "innovation" in name:
            continue  # the demo's unreachable account
        factor = 0.5 if "prod" in name else 1.8 if "sandbox" in name or "dev" in name else 1.0
        checks: dict[str, dict] = {}
        for cid in measured:
            sev = rules[cid]["severity"]
            roll = rng.random()
            if roll < 0.03:
                checks[cid] = {"status": "unknown", "note": "AccessDenied in eu-west-1"}
            elif roll < 0.03 + _FAIL[sev] * factor:
                ev = _evidence(cid, rng.choice(["eu-west-1", "eu-west-2", "af-south-1"]), rng)
                checks[cid] = {"status": "fail", "n": len(ev), "ev": ev, "note": ""}
            elif roll > 0.97:
                checks[cid] = {"status": "na", "note": "service not billed in this account"}
            else:
                checks[cid] = {"status": "pass", "note": ""}
        buckets = [
            {"name": f"access-logs-{acct['id']}", "region": "eu-west-1", "versioning": True, "lock": False,
             "replicated": False, "tags": {}, "public": False, "tls_only": True, "acls": False, "kms": False,
             "writers": []},
        ]  # fmt: skip
        for part, cid, ev in _STORY:
            if part not in name:
                continue
            if cid == "sensitive_bucket":
                buckets.append({
                    "name": f"{name}-settlement-files", "region": "eu-west-1", "versioning": "core" in name,
                    "lock": False, "replicated": "core" in name, "tags": {"DataClassification": "Confidential"},
                    "public": False, "tls_only": True, "acls": False, "kms": "core" in name,
                    "writers": ["permission set PaymentsSupport", "permission set AWSAdministratorAccess"],
                })  # fmt: skip
            else:
                checks[cid] = {"status": "fail", "n": len(ev), "ev": ev, "note": ""}
        admins = ["permission set AWSAdministratorAccess"] + (["IAM user break-glass"] if "legacy" in name else [])
        out[acct["id"]] = {
            "checks": checks,
            "facts": {
                "buckets": buckets,
                "trails": [{"name": "org-trail", "org": True, "home": "eu-west-1", "s3_writes": None}],
                "s3_rules": {"eu-west-1": []},
                "guardduty_s3": {"eu-west-1": "prod" in name},
                "iam_admins": admins,
                **_finding_facts(checks, rng),
            },
            "regions": ["eu-west-1", "eu-west-2", "us-east-1"],
            "read_at": "",
            "seconds": round(rng.uniform(20, 70), 1),
        }
    ids = list(out)
    org = {
        "scps": {
            aid: {
                "missing": []
                if i % 4
                else ["S3 Block Public Access kept on", "no new IAM users (people sign in through Identity Center)"],
                "region_deny": i % 3 != 0,
            }
            for i, aid in enumerate(ids)
        },  # fmt: skip
        "root": {"credentials": False, "sessions": False},
        "delegated": [
            {
                "id": "222222222222",
                "name": "security-tooling",
                "services": ["guardduty.amazonaws.com", "securityhub.amazonaws.com", "access-analyzer.amazonaws.com"],
            }
        ],  # fmt: skip
        "identity_center": {
            "admin_sets": ["AWSAdministratorAccess", "PlatformAdmin"],
            "owners": {},
            "admins": {
                aid: {
                    "people": sorted(rng.sample(_PEOPLE, rng.choice([2, 3, 4, 6, 9]))),
                    "direct": ["Dana Fourie"] if i % 5 == 0 else [],
                    "groups": ["aws-platform-admins"],
                }
                for i, aid in enumerate(ids)
            },
        },
        "trails": [
            {
                "name": "org-trail",
                "home": "eu-west-1",
                "logging": True,
                "s3_writes": {"all": False, "prefixes": []},
                "alerts": ["root", "aws.iam"],
            }
        ],  # fmt: skip
    }
    return {"catalog_version": catalog().get("version"), "org": org, "accounts": out}
