"""Network Traffic Review: the flow-log queries for failed TCP and the week before, what is new today, and the
review built from them, account by account."""

from test_server import H, client

from exitrisk.collectors import access
from exitrisk.demo import build_demo_scan
from exitrisk.network_review import build_network_review, port_name

V3 = ("${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} "
      "${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${tcp-flags}")  # fmt: skip


def test_tcp_query_needs_the_tcp_flags_and_counts_retried_syns_and_resets():
    assert access.tcp_query(access.DEFAULT_FORMAT) is None
    q = access.tcp_query(V3)
    assert 'f_tcp_flags = "2" and f_packets >= 3' in q
    assert 'f_tcp_flags = "4" and f_packets <= 2' in q
    assert 'f_protocol = "6"' in q and 'f_action = "ACCEPT"' in q


def test_baseline_query_takes_refusals_and_with_flags_the_failed_tcp_too():
    plain = access.baseline_query(access.DEFAULT_FORMAT)
    assert 'f_action = "REJECT"' in plain and "tcp_flags" not in plain
    assert f"limit {access.BASE_ROWS}" in plain
    assert 'f_tcp_flags = "2"' in access.baseline_query(V3)
    assert access.baseline_query("${version} ${srcaddr}") is None


class _Logs:
    """Logs Insights answering every query with the same rows."""

    def __init__(self, rows, status="Complete"):
        self.rows, self.status, self.asked = rows, status, []

    def start_query(self, **kw):
        self.asked.append(kw)
        return {"queryId": "q"}

    def get_query_results(self, queryId):  # noqa: N803
        res = [[{"field": k, "value": v} for k, v in r.items()] for r in self.rows]
        return {"status": self.status, "results": res, "statistics": {"bytesScanned": 2e9}}


def _out():
    return {"rejected": [{"src": "1.2.3.4", "dst": "10.0.0.5", "port": "22", "flows": 9},
                         {"src": "5.6.7.8", "dst": "10.0.0.5", "port": "22", "flows": 4}],
            "failed_tcp": [{"src": "10.0.0.5", "dst": "10.9.0.1", "port": "1521", "kind": "unanswered",
                            "flows": 3}]}  # fmt: skip


REJECTS = {access.DEFAULT_FORMAT: {"groups": {"flows"}, "resources": {"vpc-1"}}}


def test_new_today_marks_pairs_and_sources_the_week_before_did_not_have():
    out, stats = _out(), {}
    logs = _Logs([{"src": "1.2.3.4", "dst": "10.0.0.5", "flows": "40"}, {"src": "10.0.0.5", "dst": "10.8.0.1"}])
    access._new_today(out, REJECTS, logs, 1_000_000, stats)
    assert out["baseline"] == {"days": access.BASE_DAYS, "read": True, "full": False, "pairs": 2}
    old, fresh = out["rejected"]
    assert old["new"] is False and old["src_new"] is False
    assert fresh["new"] is True and fresh["src_new"] is True
    tcp = out["failed_tcp"][0]
    assert tcp["new"] is True and tcp["src_new"] is False  # the source failed before, to another target
    assert logs.asked[0]["startTime"] == 1_000_000 - access.BASE_DAYS * 86400 and logs.asked[0]["endTime"] == 1_000_000
    assert stats["bytes"] == 2_000_000_000


def test_new_today_marks_nothing_when_the_week_before_is_too_large_or_unread():
    out = _out()
    full = _Logs([{"src": f"10.1.{i // 250}.{i % 250}", "dst": "10.0.0.5"} for i in range(access.BASE_ROWS)])
    access._new_today(out, REJECTS, full, 1_000_000, {})
    assert out["baseline"]["full"] and not out["baseline"]["read"]
    assert all("new" not in r for r in out["rejected"] + out["failed_tcp"])
    out = _out()
    access._new_today(out, REJECTS, _Logs([], status="Failed"), 1_000_000, {})
    assert out["baseline"] == {"days": access.BASE_DAYS, "read": False}
    assert all("new" not in r for r in out["rejected"])


def _scan():
    """Two accounts: A owns 10.0.0.0/16, B owns 10.1.0.0/16; 10.200.x is no one's (on premises)."""

    def facts(cidr, flows):
        return {"access_assets": {"eu-west-1": {"vpcs": [{"id": "vpc-1", "cidrs": [cidr]}]}},
                "access_flows": {"eu-west-1": flows}}  # fmt: skip

    a = {"reject_covered": ["vpc-1"], "tcp_covered": ["vpc-1"], "insights_bytes": 4e9,
         "baseline": {"days": 7, "read": True, "full": False, "pairs": 3},
         "rejected": [
             {"src": "45.33.1.9", "dst": "10.0.0.5", "port": p, "flows": 10, "bytes": 600, "new": False}
             for p in ("22", "23", "3389", "445", "1433")
         ] + [
             {"src": "10.1.0.7", "dst": "10.0.0.5", "port": "5432", "flows": 6, "bytes": 360, "new": True},
             {"src": "10.0.0.5", "dst": "10.200.1.1", "port": "1521", "flows": 4, "bytes": 240, "new": False},
             {"src": "10.0.0.5", "dst": "10.0.0.6", "port": "8080", "flows": 2, "bytes": 120, "new": False},
         ],
         "failed_tcp": [
             {"src": "10.0.0.5", "dst": "52.1.2.3", "port": "443", "kind": "unanswered", "flows": 5,
              "bytes": 300, "new": True, "src_new": False},
         ] + [
             {"src": "10.1.0.9", "dst": "10.0.0.6", "port": str(p), "kind": "reset", "flows": 1, "bytes": 40}
             for p in range(1000, 1012)
         ]}  # fmt: skip
    b = {"reject_covered": [], "s3_only": ["vpc-2"]}
    return {"id": "s1", "accounts": [{"id": "111111111111", "name": "alpha-prod"},
                                     {"id": "222222222222", "name": "beta-prod"}],
            "assurance": {"accounts": {
                "111111111111": {"facts": facts("10.0.0.0/16", a), "checks": {}},
                "222222222222": {"facts": facts("10.1.0.0/16", b),
                                 "checks": {"flow_logs": {"status": "fail", "n": 2}}},
            }}}  # fmt: skip


def test_review_classifies_where_each_failure_was_going_and_what_kind():
    r = build_network_review(_scan())
    assert r["available"]
    a = next(x for x in r["accounts"] if x["id"] == "111111111111")
    c = a["counts"]
    assert c["refused_in_internet"] == 50
    assert c["refused_in_private"] == 6  # from beta's range
    assert c["refused_out"] == 4 and c["refused_internal"] == 2
    assert c["unanswered"] == 5 and c["reset"] == 12
    assert a["where"] == {"internet": 55, "account": 18, "onprem": 4, "own": 2}
    flow = {(x["remote"], x["class"]): x for x in a["top"]}
    assert flow[("10.1.0.7", "refused_in_private")]["remote_account"] == "beta-prod"
    assert flow[("10.200.1.1", "refused_out")]["where"] == "onprem"
    assert a["new_pairs"] == 2 and a["new_inside"] == 2
    assert a["bytes"] == 3000 + 360 + 240 + 120 + 300 + 480


def test_review_names_recon_from_outside_and_a_sweep_from_inside():
    r = build_network_review(_scan())
    src = r["sources"][0]
    assert src["ip"] == "45.33.1.9" and src["port_count"] == 5 and src["recon"]
    look = {x["id"]: x for x in r["look"]}
    texts = [x["text"] for x in look["111111111111"]["reasons"]]
    assert any(t.startswith("10.1.0.9, inside the estate") for t in texts)
    assert any("timed out" in t for t in texts)
    assert r["look"][0]["id"] == "111111111111"
    # the internet knocking alone is not a reason to look
    assert not any("refused coming in from the internet" in t.lower() for t in texts)


def test_review_coverage_names_s3_only_and_missing_flow_logs_and_the_cost():
    cov = build_network_review(_scan())["coverage"]
    assert cov["flows_read"] == 1 and cov["tcp_read"] == 1 and cov["baseline_read"] == 1
    assert cov["s3_only"] == 1 and cov["s3_accounts"] == 1
    assert cov["no_flow_logs"] == 2 and cov["no_flow_log_accounts"] == 1
    assert cov["insights_cost"] == 0.02


def test_review_without_assurance_is_unavailable_and_ports_are_named():
    r = build_network_review({"id": "x", "accounts": []})
    assert not r["available"] and "Cloud Assurance" in r["reason"]
    assert port_name("22") == "22 (SSH)" and port_name("41000") == "41000"


def test_demo_review_has_new_failures_recon_and_every_class():
    r = build_network_review(build_demo_scan(6))
    assert r["new_count"] > 0 and r["totals"]["recon_accounts"] > 0
    assert {c["key"] for c in r["totals"]["classes"]} == {c["key"] for c in r["classes"]}


def test_network_endpoint():
    c = client()
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    r = c.post("/api/network", headers=H, json={"scan_id": scan_id, "filter": {"include": "prod"}})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] and all("prod" in a["name"] for a in body["accounts"])
    assert c.post("/api/network", headers=H, json={"scan_id": "nope"}).status_code == 404
    assert c.post("/api/network", json={"scan_id": scan_id}).status_code in (403, 400)


def _link_scan(links: dict, assets: dict | None = None, dx: list | None = None, network: dict | None = None):
    f = {"access_failures": {"eu-west-1": {"metrics": {}, "links": links, **({"dx": dx} if dx else {})}},
         "access_assets": {"eu-west-1": assets or {}}, "access_network": {"eu-west-1": network or {}}}  # fmt: skip
    return {"id": "s", "accounts": [{"id": "111111111111", "name": "net-prod", "tags": {"Owner": "Ana"}}],
            "assurance": {"accounts": {"111111111111": {"facts": f, "checks": {}}}}}  # fmt: skip


def _h(vals):
    return {"sum": sum(vals), "max": max(vals), "min": min(vals), "n": len(vals),
            "hours": [[f"t{i}", v] for i, v in enumerate(vals)]}  # fmt: skip


def test_links_read_from_metrics_are_kept_by_family_and_resource():
    q = access.link_queries()
    assert {x["_fam"] for x in q} == set(access.LINK_LABEL)
    tgwa = next(x for x in q if x["_key"] == "tgwa_hole")
    assert "TransitGatewayAttachment" in tgwa["Expression"] and "|" in tgwa["Label"]
    from datetime import datetime, timezone

    t = datetime(2026, 11, 17, tzinfo=timezone.utc)
    data = {tgwa["Id"]: {"tgw-1|tgw-attach-1": [(t, 5.0), (t, 7.0)]}}
    out = access.link_totals(q, data)
    assert out["tgwa"]["tgw-1|tgw-attach-1"]["tgwa_hole"]["sum"] == 12
    assert "hours" not in out["tgwa"]["tgw-1|tgw-attach-1"]["tgwa_hole"]


def test_direct_connect_down_hours_errors_and_near_full_are_faults():
    dx = [{"id": "dxcon-1", "name": "dc1", "location": "L1", "bandwidth": "1Gbps", "state": "available"}]
    links = {"dx": {"dxcon-1": {"dx_state": _h([1, 0, 0, 1]), "dx_in_max": _h([9e8, 1e8, 1e8, 1e8]),
                                "dx_out_max": _h([1e8] * 4), "dx_in": _h([5e8] * 4),
                                "dx_crc": {"sum": 12, "n": 4}}}}  # fmt: skip
    r = build_network_review(_link_scan(links, dx=dx))
    x = r["links"]["dx"][0]
    texts = " ".join(f["text"] for f in x["flags"])
    assert x["down_hours"] == 2 and "Down in 2 of the last 4 hours" in texts and "down now" not in texts
    assert "CRC" in texts and "90%" in texts and x["peak_pct"] == 90
    assert x["account"]["owner"] == "Ana"
    look = r["look"][0]
    assert any(m["kind"] == "health" and m["link"] == "dx" for m in look["reasons"])


def test_a_vpn_on_one_tunnel_and_a_quiet_nat_gateway():
    links = {"vpn": {"vpn-1|1.1.1.1": {"vpn_state": _h([1, 1]), "vpn_in": {"sum": 10, "n": 2}},
                     "vpn-1|2.2.2.2": {"vpn_state": _h([0, 0])}},
             "nat": {"nat-1": {"nat_try": _h([1000.0]), "nat_made": _h([990.0])}}}  # fmt: skip
    assets = {"vpns": [{"id": "vpn-1", "name": "DC", "tunnels": 2, "up": 1, "routes": ["192.168.0.0/16"]}]}
    r = build_network_review(_link_scan(links, assets))
    vpn = r["links"]["vpn"][0]
    assert vpn["up"] == 1 and "no second path" in vpn["flags"][0]["text"]
    nat = r["links"]["nat"][0]
    assert nat["unanswered"] == 10 and not nat["flags"]  # 10 of 1,000 is not a fault


def test_transit_gateway_drops_name_the_attachment_and_its_account():
    links = {"tgw": {"tgw-1": {"tgw_hole": {"sum": 50, "n": 1}, "tgw_in": _h([1.0])}},
             "tgwa": {"tgw-1|att-1": {"tgwa_hole": {"sum": 50, "n": 1}, "tgwa_in": _h([1.0])},
                      "tgw-1|att-2": {"tgwa_in": _h([0.0])}}}  # fmt: skip
    network = {"tgw_attachments": [{"id": "att-1", "tgw": "tgw-1", "tgw_owner": "111111111111",
                                    "owner": "111111111111", "type": "vpc", "resource": "vpc-1"},
                                   {"id": "att-9", "tgw": "tgw-out", "tgw_owner": "999999999999",
                                    "owner": "111111111111", "type": "vpc", "resource": "vpc-1"}]}  # fmt: skip
    r = build_network_review(_link_scan(links, network=network))
    g = r["links"]["tgw"][0]
    assert "from att-1 (vpc of net-prod)" in g["flags"][0]["text"]
    assert any("carried nothing" in f["text"] for f in g["flags"])
    assert r["links"]["tgw_outside"][0]["id"] == "tgw-out"


def test_privatelink_resets_are_faults_on_both_sides():
    links = {"vpcs": {"svc-1": {"vpcs_rst": {"sum": 30, "n": 1}}},
             "vpcse": {"svc-1|vpce-9": {"vpcse_rst": {"sum": 30, "n": 1}, "vpcse_bytes": {"sum": 5, "n": 1}}},
             "vpce": {"vpce-2|com.amazonaws.vpce.eu-west-1.svc-1|vpc-1":
                      {"vpce_drop": {"sum": 4, "n": 1}}}}  # fmt: skip
    r = build_network_review(_link_scan(links))
    s, e = r["links"]["pl_services"][0], r["links"]["pl_endpoints"][0]
    assert "most to vpce-9" in s["flags"][0]["text"]
    assert e["service"].endswith("svc-1") and "4 packets dropped" in e["flags"][0]["text"]


def test_data_centre_traffic_is_named_from_vpn_routes_and_owner_shown():
    scan = _scan()
    f = scan["assurance"]["accounts"]["111111111111"]["facts"]
    f["access_flows"]["eu-west-1"]["rows"] = [{"src": "10.0.0.5", "dst": "10.200.1.1", "port": "1521",
                                                "bytes": 5000, "flows": 7}]  # fmt: skip
    f["access_assets"]["eu-west-1"]["vpns"] = [{"id": "vpn-1", "name": "JHB", "routes": ["10.200.0.0/16"]}]
    d = build_network_review(scan)["datacentre"]
    assert d["top"][0]["remote_name"] == "Behind VPN JHB" and d["top"][0]["bytes"] == 5000
    assert d["accounts"][0]["bytes_out"] == 5000 and d["accounts"][0]["failed"] == 4
    assert d["failed"][0]["remote_name"] == "Behind VPN JHB"


def test_every_kind_has_a_unit_and_sources_say_internal_or_external():
    r = build_network_review(_scan())
    assert all(c["unit"] for c in r["classes"])
    kinds = {s["ip"]: s for s in r["sources"]}
    assert kinds["45.33.1.9"]["internal"] is False and kinds["45.33.1.9"]["where"] == "internet"
    inside = kinds["10.1.0.9"]
    assert inside["internal"] and inside["source_account"]["name"] == "beta-prod"
