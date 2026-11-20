"""Who an internet address belongs to: AWS (and which service), a SaaS provider, or a network by its AS number.

Everything is read from public lists downloaded to the data directory and looked up locally, so no address
from your estate ever leaves the machine:

* AWS's own ranges (ip-ranges.json), with the service and region of each;
* the ranges SaaS providers publish (Cloudflare, GitHub, Google, Atlassian, Okta, Datadog, Fastly, Oracle Cloud,
  Zscaler);
* every routed IPv4 range with its AS number, owner and country (iptoasn.com, public domain).

AWS's list and the SaaS lists are read again after a day, the AS list after a week. Until a list has been read
once, a few well-known ranges stand in, so the report still labels the commonest sources. ``refresh`` downloads
(called from a background thread); ``get`` never waits for the network.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import threading
import time
import urllib.request
from array import array
from bisect import bisect_right

from .config import settings
from .logging_config import get_logger

log = get_logger("ipintel")

AGENT = "aws-risk-review"
DAY = 86400
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
# (name, url, how to read it). GitHub Actions runs on Azure's shared ranges, so it is left out: it would
# name every Azure address GitHub.
SAAS_FEEDS = [
    ("Cloudflare", "https://www.cloudflare.com/ips-v4", "lines"),
    ("GitHub", "https://api.github.com/meta", "github"),
    ("Google Cloud (a customer's server)", "https://www.gstatic.com/ipranges/cloud.json", "google"),
    ("Google", "https://www.gstatic.com/ipranges/goog.json", "google"),
    ("Atlassian", "https://ip-ranges.atlassian.com/", "atlassian"),
    ("Okta", "https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json", "walk"),
    ("Datadog", "https://ip-ranges.datadoghq.com/", "datadog"),
    ("Fastly", "https://api.fastly.com/public-ip-list", "walk"),
    ("Oracle Cloud (a customer's server)", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", "walk"),
]
GITHUB_KEYS = ("hooks", "web", "api", "git", "packages", "pages", "importer", "dependabot")
# Networks owned by a SaaS or cloud provider, named when no published list matched.
SAAS_ASNS = {
    8075: "Microsoft", 15169: "Google", 14340: "Salesforce", 13335: "Cloudflare", 20940: "Akamai", 16625: "Akamai",
    54113: "Fastly", 36459: "GitHub", 22616: "Zscaler", 32934: "Meta", 19679: "Dropbox", 2635: "Automattic",
}  # fmt: skip
# Until the lists are first read: a few ranges whose owner is well known.
SEED_SAAS = [
    ("104.16.0.0/13", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"), ("140.82.112.0/20", "GitHub (hooks)"),
    ("192.30.252.0/22", "GitHub (hooks)"), ("165.225.0.0/17", "Zscaler"), ("13.108.0.0/14", "Salesforce"),
    ("8.8.8.0/24", "Google"),
]  # fmt: skip
SEED_AWS = [
    ("54.228.16.0/26", "ROUTE53_HEALTHCHECKS", "eu-west-1"), ("54.232.40.64/26", "ROUTE53_HEALTHCHECKS", "sa-east-1"),
    ("13.244.0.0/15", "EC2", "af-south-1"), ("15.188.0.0/16", "EC2", "eu-west-3"), ("52.95.0.0/16", "AMAZON", ""),
    ("130.176.0.0/16", "CLOUDFRONT_ORIGIN_FACING", "GLOBAL"), ("3.0.0.0/9", "AMAZON", ""),
]  # fmt: skip
SEED_ASN = [
    ("162.142.125.0", "162.142.125.255", 398324, "US", "CENSYS-ARIN-01"),
    ("165.225.0.0", "165.225.127.255", 22616, "US", "ZSCALER-INC"),
    ("140.82.112.0", "140.82.127.255", 36459, "US", "GITHUB"),
    ("104.16.0.0", "104.23.255.255", 13335, "US", "CLOUDFLARENET"),
    ("13.108.0.0", "13.111.255.255", 14340, "US", "SALESFORCE"),
]  # fmt: skip
# AWS service names that are more telling than AMAZON, the catch-all every range also carries.
AWS_SERVICE = {
    "ROUTE53_HEALTHCHECKS": "Route 53 health checks", "CLOUDFRONT_ORIGIN_FACING": "CloudFront",
    "CLOUDFRONT": "CloudFront", "EC2": "EC2 (any AWS customer's server, or Lambda outside a VPC)",
    "API_GATEWAY": "API Gateway", "S3": "S3", "DYNAMODB": "DynamoDB", "GLOBALACCELERATOR": "Global Accelerator",
    "ROUTE53": "Route 53", "ROUTE53_RESOLVER": "Route 53 Resolver", "CODEBUILD": "CodeBuild",
    "EC2_INSTANCE_CONNECT": "EC2 Instance Connect", "WORKSPACES_GATEWAYS": "WorkSpaces", "CLOUD9": "Cloud9",
    "KINESIS_VIDEO_STREAMS": "Kinesis Video Streams", "CHIME_VOICECONNECTOR": "Chime", "AMAZON_CONNECT": "Connect",
    "AMAZON_APPFLOW": "AppFlow", "EBS": "EBS", "AMAZON": "AWS",
}  # fmt: skip

_lock = threading.Lock()
_refreshing = threading.Event()
_memo: dict = {}


def _dir():
    d = settings.data_dir / "ipintel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get(url: str, timeout: float = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": AGENT})  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


def _nets(values) -> list[str]:
    out = []
    for v in values:
        try:
            n = ipaddress.ip_network(str(v).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen:
            out.append(str(n))
    return out


def _walk(node, out: list) -> None:
    if isinstance(node, dict):
        for v in node.values():
            _walk(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, out)
    elif isinstance(node, str) and "/" in node:
        out += _nets([node])


def parse_feed(name: str, how: str, raw: bytes) -> list[tuple[str, str]]:
    """(cidr, label) pairs from one provider's published list."""
    if how == "lines":
        return [(c, name) for c in _nets(raw.decode("utf-8", "replace").split())]
    doc = json.loads(raw)
    if how == "github":
        return [(c, f"GitHub ({k})") for k in GITHUB_KEYS for c in _nets(doc.get(k) or [])]
    if how == "google":
        return [(c, name) for c in _nets(p.get("ipv4Prefix") for p in doc.get("prefixes") or [])]
    if how == "atlassian":
        return [(c, name) for c in _nets(i.get("cidr") for i in doc.get("items") or [])]
    if how == "datadog":
        return [(c, f"Datadog ({k})") for k, v in doc.items() if isinstance(v, dict)
                for c in _nets(v.get("prefixes_ipv4") or [])]  # fmt: skip
    found: list = []
    _walk(doc, found)
    return [(c, name) for c in found]


def parse_asn(raw: bytes) -> list[tuple]:
    """(start, end, asn, country, owner) rows of iptoasn's TSV, routed ranges only."""
    rows = []
    for line in gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or parts[2] == "0":
            continue
        rows.append((parts[0], parts[1], int(parts[2]), parts[3], parts[4]))
    return rows


def _fresh(path, age: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime < age
    except OSError:
        return False


def refresh(force: bool = False) -> dict:
    """Download whichever lists are older than their refresh age; keep the old copy when a download fails."""
    d = _dir()
    got = {}
    if force or not _fresh(d / "aws.json", DAY):
        try:
            doc = json.loads(_get(AWS_URL))
            rows = [(p["ip_prefix"], p.get("service", ""), p.get("region", "")) for p in doc.get("prefixes") or []]
            (d / "aws.json").write_text(json.dumps(rows))
            got["aws"] = len(rows)
        except (OSError, ValueError, KeyError) as exc:
            log.info("AWS ranges not read: %s", exc)
    if force or not _fresh(d / "saas.json", DAY):
        pairs: list = []
        for name, url, how in SAAS_FEEDS:
            try:
                pairs += parse_feed(name, how, _get(url, 15))
            except (OSError, ValueError, AttributeError) as exc:
                log.info("%s ranges not read: %s", name, exc)
        try:
            from . import zscaler

            pairs += [(c, "Zscaler") for c in _nets(zscaler.ranges())]
        except Exception as exc:  # noqa: BLE001 - one list missing must not stop the others
            log.info("Zscaler ranges not read: %s", exc)
        if pairs:
            (d / "saas.json").write_text(json.dumps(pairs))
            got["saas"] = len(pairs)
    if force or not _fresh(d / "asn.tsv.gz", 7 * DAY):
        try:
            raw = _get(ASN_URL, 90)
            parse_asn(raw)[:1]  # a broken download is not kept
            (d / "asn.tsv.gz").write_bytes(raw)
            got["asn"] = True
        except (OSError, ValueError, EOFError) as exc:
            log.info("AS number list not read: %s", exc)
    if got:
        with _lock:
            _memo.clear()
    return got


def refresh_async() -> None:
    """Start a background download when a list is stale; returns at once."""
    d = _dir()
    stale = not (_fresh(d / "aws.json", DAY) and _fresh(d / "saas.json", DAY) and _fresh(d / "asn.tsv.gz", 7 * DAY))
    if not stale or _refreshing.is_set():
        return
    _refreshing.set()

    def run():
        try:
            refresh()
        finally:
            _refreshing.clear()

    threading.Thread(target=run, daemon=True, name="ipintel-refresh").start()


class PrefixIndex:
    """Longest-prefix match over many CIDRs: one dict per prefix length."""

    def __init__(self, rows) -> None:
        self.by_len: dict[int, dict[int, object]] = {}
        for cidr, payload in rows:
            try:
                n = ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                continue
            self.by_len.setdefault(n.prefixlen, {}).setdefault(int(n.network_address), payload)
        self.lens = sorted(self.by_len, reverse=True)

    def get(self, ip: int):
        for plen in self.lens:
            hit = self.by_len[plen].get(ip >> (32 - plen) << (32 - plen) if plen else 0)
            if hit is not None:
                return hit
        return None

    def intervals(self) -> list[tuple[int, int]]:
        return merge([(k, k + (1 << (32 - p)) - 1) for p, d in self.by_len.items() for k in d])


class Intel:
    """Every lookup, built once from the downloaded lists (or the stand-ins)."""

    def __init__(self, aws_rows, saas_rows, asn_rows) -> None:
        # The most telling service wins: AMAZON is every range's catch-all, so it ranks last.
        best: dict[str, tuple] = {}
        for cidr, svc, region in aws_rows:
            cur = best.get(cidr)
            if cur is None or (cur[0] == "AMAZON" and svc != "AMAZON"):
                best[cidr] = (svc, region)
        self.aws = PrefixIndex(best.items())
        self.saas = PrefixIndex(saas_rows)
        self.asn_start = array("I")
        self.asn_end = array("I")
        self.asn_meta: list[tuple] = []
        for start, end, asn, cc, owner in sorted(asn_rows, key=lambda r: int(ipaddress.IPv4Address(r[0]))):
            try:
                s, e = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
            except ValueError:
                continue
            self.asn_start.append(s)
            self.asn_end.append(e)
            self.asn_meta.append((asn, cc, owner))
        self.counts = {"aws": len(best), "saas": len(saas_rows), "asn": len(self.asn_meta)}
        self._aws_iv: list | None = None

    def asn(self, ip: int) -> dict | None:
        i = bisect_right(self.asn_start, ip) - 1
        if i < 0 or ip > self.asn_end[i]:
            return None
        asn, cc, owner = self.asn_meta[i]
        return {"asn": asn, "country": cc, "owner": owner}

    def aws_intervals(self) -> list[tuple[int, int]]:
        if self._aws_iv is None:
            self._aws_iv = self.aws.intervals()
        return self._aws_iv

    def label(self, ip: str) -> dict:
        """{kind: aws | saas | internet, name, service, region, asn, country, owner} for a public address."""
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return {"kind": "internet", "name": ip}
        a = self.asn(n) or {}
        out = {"asn": a.get("asn"), "country": a.get("country", ""), "owner": a.get("owner", "")}
        hit = self.aws.get(n)
        if hit:
            svc, region = hit
            name = AWS_SERVICE.get(svc, svc.replace("_", " ").title())
            return {**out, "kind": "aws", "service": svc, "region": region,
                    "name": f"AWS {name}" + (f", {region}" if region and region != "GLOBAL" else "")}  # fmt: skip
        hit = self.saas.get(n)
        if hit:
            return {**out, "kind": "saas", "name": hit}
        if a.get("asn") in SAAS_ASNS:
            return {**out, "kind": "saas", "name": SAAS_ASNS[a["asn"]]}
        owner = a.get("owner") or ""
        return {**out, "kind": "internet", "name": f"AS{a['asn']} {owner}".strip() if a else "Unknown network"}


def get() -> Intel:
    """The lookups from whatever lists are on disk (the stand-ins for any not yet read)."""
    d = _dir()
    key = tuple(
        (p.name, p.stat().st_mtime) if p.exists() else (p.name, 0)
        for p in (d / "aws.json", d / "saas.json", d / "asn.tsv.gz")
    )
    with _lock:
        if _memo.get("key") == key:
            return _memo["intel"]
    aws_rows = _read_json(d / "aws.json") or SEED_AWS
    saas_rows = _read_json(d / "saas.json") or SEED_SAAS
    asn_rows = SEED_ASN
    try:
        asn_rows = parse_asn((d / "asn.tsv.gz").read_bytes()) or SEED_ASN
    except (OSError, ValueError, EOFError):
        pass
    intel = Intel(aws_rows, saas_rows, asn_rows)
    intel.counts["seed"] = [n for n, rows, seed in (("aws", aws_rows, SEED_AWS), ("saas", saas_rows, SEED_SAAS),
                                                    ("asn", asn_rows, SEED_ASN)) if rows is seed]  # fmt: skip
    with _lock:
        _memo.update(key=key, intel=intel)
    return intel


def _read_json(path):
    try:
        return [tuple(r) for r in json.loads(path.read_text())]
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------------------------- interval sets
# An address set as sorted, non-overlapping (first, last) integer pairs: how address space is counted.


def merge(iv) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for s, e in sorted(iv):
        if out and s <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def intersect(a, b) -> list[tuple[int, int]]:
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        s, e = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if s <= e:
            out.append((s, e))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a, b) -> list[tuple[int, int]]:
    out, j = [], 0
    for s, e in a:
        cur = s
        while j < len(b) and b[j][1] < cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] <= e:
            if b[k][0] > cur:
                out.append((cur, b[k][0] - 1))
            cur = max(cur, b[k][1] + 1)
            k += 1
        if cur <= e:
            out.append((cur, e))
    return out


def size(a) -> int:
    return sum(e - s + 1 for s, e in a)


def cidr_iv(cidr) -> tuple[int, int] | None:
    try:
        n = ipaddress.IPv4Network(str(cidr), strict=False)
    except ValueError:
        return None
    return int(n.network_address), int(n.broadcast_address)
