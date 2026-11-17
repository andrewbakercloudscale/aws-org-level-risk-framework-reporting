"""Account map: the assets that move data in and out of one account, where they lead, transit gateway
routing, and flow-log evidence placed on the links it crossed."""

import pytest
from test_access_graph import HUB, OWN, PEER, VENDOR, _net, _scan
from test_assurance import FakeClient, _ctx
from test_server import H, client

import exitrisk.collectors.assurance as checks
from exitrisk.access_graph import build_access
from exitrisk.account_map import build_account_map, human_bytes
from exitrisk.collectors import access
from exitrisk.demo import build_demo_scan
from exitrisk.scanner import ScanParams

THIRD = "444444444444"


# ---------------------------------------------------------------------------------- collector


def test_route_targets_and_subnet_tables():
    tables = [
        {"RouteTableId": "rtb-main", "VpcId": "vpc-1", "Associations": [{"Main": True}], "Routes": [
            {"DestinationCidrBlock": "10.1.0.0/16", "GatewayId": "local"},
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
            {"DestinationCidrBlock": "10.0.0.0/8", "TransitGatewayId": "tgw-1"},
            {"DestinationPrefixListId": "pl-s3", "GatewayId": "vpce-s3"},
            {"DestinationCidrBlock": "10.9.0.0/16", "VpcPeeringConnectionId": "pcx-1", "State": "blackhole"}]},
        {"RouteTableId": "rtb-pub", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-pub"}], "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]},
    ]  # fmt: skip
    out, subnet_rt = access.route_tables(tables)
    assert subnet_rt == {"subnet-pub": "rtb-pub"}
    main = out[0]
    assert main["main"] and [(r["kind"], r["target"]) for r in main["routes"]] == [
        ("nat", "nat-1"), ("tgw", "tgw-1"), ("vpce", "vpce-s3"), ("pcx", "pcx-1")]  # fmt: skip
    assert main["routes"][-1]["blackhole"] and main["routes"][2]["dst"] == "pl-s3"
    assert out[1]["routes"][0]["kind"] == "igw"


def _assets_ec2(**extra):
    answers = {
        "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.1.0.0/16",
                                    "Tags": [{"Key": "Name", "Value": "app"}]}]},
        "describe_route_tables": {"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1",
                                                   "Associations": [{"Main": True}],
                                                   "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                                                               "NatGatewayId": "nat-1"}]}]},
        "describe_subnets": {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.1.1.0/24"}]},
        "describe_internet_gateways": {"InternetGateways": [
            {"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1", "State": "available"}]},
            {"InternetGatewayId": "igw-detached", "Attachments": []}]},
        "describe_egress_only_internet_gateways": {"EgressOnlyInternetGateways": []},
        "describe_nat_gateways": {"NatGateways": [{"NatGatewayId": "nat-1", "VpcId": "vpc-1", "SubnetId": "subnet-1",
                                                   "NatGatewayAddresses": [{"PublicIp": "52.1.1.1",
                                                                            "PrivateIp": "10.1.1.5"}]}]},
        "describe_vpn_gateways": {"VpnGateways": [{"VpnGatewayId": "vgw-1", "State": "available",
                                                   "VpcAttachments": [{"VpcId": "vpc-1", "State": "attached"}]}]},
        "describe_customer_gateways": {"CustomerGateways": [{"CustomerGatewayId": "cgw-1", "IpAddress": "196.1.1.1"}]},
        "describe_vpn_connections": {"VpnConnections": [
            {"VpnConnectionId": "vpn-1", "State": "available", "VpnGatewayId": "vgw-1", "CustomerGatewayId": "cgw-1",
             "VgwTelemetry": [{"Status": "UP"}, {"Status": "DOWN"}]}]},
        "describe_vpc_endpoints": {"VpcEndpoints": [
            {"VpcEndpointId": "vpce-s3", "ServiceName": "com.amazonaws.eu-west-1.s3", "VpcId": "vpc-1",
             "VpcEndpointType": "Gateway", "State": "available",
             "PolicyDocument": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}'},
            {"VpcEndpointId": "vpce-pl", "ServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-1",
             "State": "available"}]},
        "describe_network_interfaces": {"NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1", "Association": {"PublicIp": "34.1.1.1"},
             "Attachment": {"InstanceId": "i-1"}, "Groups": [{"GroupId": "sg-1"}]},
            {"NetworkInterfaceId": "eni-2", "VpcId": "vpc-1", "Association": {"PublicIp": "52.1.1.1"},
             "InterfaceType": "nat_gateway"}]},
        **extra,
    }  # fmt: skip
    return FakeClient(answers)


def test_assets_task_reads_gateways_and_names_what_was_refused():
    elb = FakeClient({"describe_load_balancers": {"LoadBalancers": [
        {"LoadBalancerName": "web", "Scheme": "internet-facing", "Type": "application", "VpcId": "vpc-1",
         "DNSName": "web.elb"},
        {"LoadBalancerName": "inner", "Scheme": "internal"}]}})  # fmt: skip
    ctx = _ctx({"ec2": _assets_ec2(), "elbv2": elb})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "access-assets"), "eu-west-1")
    assert not ctx.issues
    x = ctx.r.facts["access_assets"]["eu-west-1"]
    assert x["vpcs"] == [{"id": "vpc-1", "name": "app", "cidrs": ["10.1.0.0/16"], "default": False}]
    assert [g["id"] for g in x["igws"]] == ["igw-1"]  # a detached gateway moves nothing
    assert x["nats"][0]["public_ip"] == "52.1.1.1" and x["nats"][0]["private_ip"] == "10.1.1.5"
    assert x["subnets"] == [{"id": "subnet-1", "vpc": "vpc-1", "cidr": "10.1.1.0/24", "rt": "rtb-1"}]
    assert x["vpns"][0] | {} == {"id": "vpn-1", "gateway": "vgw-1", "customer_ip": "196.1.1.1", "name": "",
                                 "tunnels": 2, "up": 1, "routes": []}  # fmt: skip
    assert x["aws_endpoints"] == [{"id": "vpce-s3", "service": "s3", "vpc": "vpc-1", "type": "Gateway",
                                   "open_policy": True}]  # fmt: skip
    assert [(p["id"], p["what"]) for p in x["public_ips"]] == [("eni-1", "EC2 instance"), ("eni-2", "NAT gateway")]
    assert [lb["name"] for lb in x["lbs"]] == ["web"]
    refused = " ".join(x["refused"])
    for what in (
        "transit gateway peerings",
        "transit gateway route tables",
        "API Gateway",
        "AWS Transfer",
        "Direct Connect",
    ):
        assert what in refused  # optional reads refused: named, the map still stands


def test_assets_task_reads_transit_gateway_route_tables():
    ec2 = _assets_ec2(
        describe_transit_gateway_peering_attachments={"TransitGatewayPeeringAttachments": [
            {"TransitGatewayAttachmentId": "tgw-attach-p", "State": "available",
             "RequesterTgwInfo": {"TransitGatewayId": "tgw-1", "OwnerId": "111111111111", "Region": "eu-west-1"},
             "AccepterTgwInfo": {"TransitGatewayId": "tgw-9", "OwnerId": PEER, "Region": "us-east-1"}}]},
        describe_transit_gateway_route_tables={"TransitGatewayRouteTables": [
            {"TransitGatewayRouteTableId": "tgw-rtb-1", "TransitGatewayId": "tgw-1", "State": "available",
             "Tags": [{"Key": "Name", "Value": "prod"}]}]},
        get_transit_gateway_route_table_associations={"Associations": [{"TransitGatewayAttachmentId": "att-a"}]},
        get_transit_gateway_route_table_propagations={"TransitGatewayRouteTablePropagations": [
            {"TransitGatewayAttachmentId": "att-b"}]},
        search_transit_gateway_routes={"Routes": [
            {"DestinationCidrBlock": "10.2.0.0/16", "Type": "propagated", "State": "active",
             "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": "att-b"}]},
            {"DestinationCidrBlock": "10.9.0.0/16", "Type": "static", "State": "blackhole"}]},
    )  # fmt: skip
    ctx = _ctx({"ec2": ec2})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "access-assets"), "eu-west-1")
    x = ctx.r.facts["access_assets"]["eu-west-1"]
    assert x["tgw_peerings"] == [{"id": "tgw-attach-p", "tgw": "tgw-1", "peer_tgw": "tgw-9", "peer_owner": PEER,
                                  "peer_region": "us-east-1"}]  # fmt: skip
    t = x["tgw_tables"][0]
    assert (t["name"], t["associations"], t["propagations"]) == ("prod", ["att-a"], ["att-b"])
    assert t["routes"] == [{"dst": "10.2.0.0/16", "attachments": ["att-b"], "type": "propagated", "blackhole": False},
                           {"dst": "10.9.0.0/16", "attachments": [], "type": "static", "blackhole": True}]  # fmt: skip


def test_flow_query_follows_the_format_and_refuses_one_without_the_fields():
    q = access.flow_query("")
    assert q.startswith('parse @message "* * * * * * * * * * * * * *"') and "f_srcaddr as src" in q
    v5 = "${version} ${srcaddr} ${dstaddr} ${pkt-srcaddr} ${pkt-dstaddr} ${dstport} ${bytes} ${action}"
    q5 = access.flow_query(v5)
    assert "f_pkt_srcaddr as src" in q5 and "f_pkt_dstaddr as dst" in q5  # the real ends behind a NAT
    assert access.flow_query("${version} ${srcaddr} ${bytes}") is None


def test_flows_read_only_when_asked_and_s3_logs_named():
    calls = []
    logs = FakeClient({
        "start_query": lambda **kw: calls.append(kw["queryString"]) or {"queryId": f"q{len(calls)}"},
        "get_query_results": lambda queryId: {"status": "Complete", "results": (  # noqa: N803
            [[{"field": "src", "value": "10.1.1.9"}, {"field": "dst", "value": "8.8.8.8"},
              {"field": "port", "value": "443"}, {"field": "bytes", "value": "1000"}, {"field": "flows", "value": "3"}]]
            if queryId == "q1" else [[{"field": "bytes", "value": "1500"}]])},
    })  # fmt: skip
    ec2 = FakeClient({"describe_flow_logs": {"FlowLogs": [
        {"FlowLogStatus": "ACTIVE", "ResourceId": "vpc-1", "LogDestinationType": "cloud-watch-logs",
         "LogGroupName": "flows"},
        {"FlowLogStatus": "ACTIVE", "ResourceId": "vpc-2", "LogDestinationType": "s3"}]}})  # fmt: skip
    task = next(t for t in checks.REGION_TASKS if t[0] == "access-flows")
    off = _ctx({"ec2": ec2, "logs": logs})
    checks._run(off, task, "eu-west-1")
    assert "access_flows" not in off.r.facts and not calls  # costs money: never unless the scan asks
    on = _ctx({"ec2": ec2, "logs": logs}, info={"flows": True})
    checks._run(on, task, "eu-west-1")
    f = on.r.facts["access_flows"]["eu-west-1"]
    assert f["rows"] == [{"src": "10.1.1.9", "dst": "8.8.8.8", "port": "443", "bytes": 1000, "flows": 3}]
    assert f["total_bytes"] == 1500 and f["covered"] == ["vpc-1"] and f["s3_only"] == ["vpc-2"]


def test_flows_need_assurance():
    with pytest.raises(ValueError, match="Cloud Assurance"):
        ScanParams(access_flows=True).validate()
    ScanParams(access_flows=True, assurance=True).validate()


# ---------------------------------------------------------------------------------- the map


def _assets(cidr, vpc="vpc-1", **kw):
    o2 = cidr.split(".")[1]
    base = {"vpcs": [{"id": vpc, "name": "", "cidrs": [cidr], "default": False}],
            "subnets": [{"id": "subnet-a", "vpc": vpc, "cidr": f"10.{o2}.1.0/24", "rt": "rtb-a"}],
            "routes": [], "igws": [], "eigws": [], "nats": [], "vgws": [], "vpns": [], "dx_vifs": [],
            "aws_endpoints": [], "public_ips": [], "lbs": [], "apis": [], "transfer": []}  # fmt: skip
    base.update(kw)
    return {"eu-west-1": base}


def _att(aid, owner, tgw="tgw-1", tgw_owner=HUB, kind="vpc"):
    return {"id": aid, "tgw": tgw, "tgw_owner": tgw_owner, "owner": owner, "type": kind, "resource": f"vpc-{owner[:3]}"}


def _links(m, src=None):
    return {(x["from"], x["to"]): x for x in m["links"] if src is None or x["from"] == src}


def test_internet_nat_and_public_addresses_lead_to_the_internet():
    scan = _scan({OWN: {
        "access_network": _net("10.1.0.0/16"),
        "access_assets": _assets("10.1.0.0/16", igws=[{"id": "igw-1", "vpc": "vpc-1"}],
                                 nats=[{"id": "nat-1", "vpc": "vpc-1", "type": "public", "public_ip": "52.1.1.1"}],
                                 lbs=[{"name": "web", "type": "application", "vpc": "vpc-1", "dns": "web.elb"}],
                                 public_ips=[{"id": "eni-1", "ip": "34.1.1.1", "vpc": "vpc-1", "what": "EC2 instance"},
                                             {"id": "eni-2", "ip": "52.1.1.1", "vpc": "vpc-1",
                                              "what": "NAT gateway"}]),
    }})  # fmt: skip
    m = build_account_map(scan, OWN)
    links = _links(m)
    assert links[("igw-1", "internet")]["dir"] == "both"
    assert links[("nat-1", "internet")]["dir"] == "out"
    assert links[("lb:eu-west-1:web", "internet")]["dir"] == "in"
    assert links[("vpc:vpc-1", "nat-1")]["dir"] == "out"
    kinds = {n["id"]: n["kind"] for n in m["nodes"]}
    assert kinds["pub:vpc-1:EC2 instance"] == "public-ip" and "pub:vpc-1:NAT gateway" not in kinds  # shown as NAT
    igw = next(n for n in m["nodes"] if n["id"] == "igw-1")
    assert "no route table sends traffic to it" in igw["flags"]


def test_transit_gateway_followed_through_its_route_tables():
    tables = [
        {"id": "rtb-prod", "tgw": "tgw-1", "name": "prod", "associations": ["att-own", "att-peer"],
         "propagations": [], "routes_cut": False, "routes": [
             {"dst": "10.2.0.0/16", "attachments": ["att-peer"], "type": "propagated", "blackhole": False},
             {"dst": "10.1.0.0/16", "attachments": ["att-own"], "type": "propagated", "blackhole": False},
             {"dst": "192.168.0.0/16", "attachments": ["att-vpn"], "type": "static", "blackhole": False},
             {"dst": "10.66.0.0/16", "attachments": [], "type": "static", "blackhole": True}]},
        {"id": "rtb-iso", "tgw": "tgw-1", "name": "isolated", "associations": ["att-third"], "propagations": [],
         "routes_cut": False, "routes": []},
    ]  # fmt: skip
    hub_net = _net("10.0.0.0/16", tgw_attachments=[_att("att-own", OWN), _att("att-peer", PEER),
                                                   _att("att-third", THIRD),
                                                   _att("att-vpn", HUB, kind="vpn")])  # fmt: skip
    scan = _scan({
        OWN: {"access_network": _net("10.1.0.0/16", tgw_attachments=[_att("att-own", OWN)]),
              "access_assets": _assets("10.1.0.0/16")},
        PEER: {"access_network": _net("10.2.0.0/16", tgw_attachments=[_att("att-peer", PEER)])},
        THIRD: {"access_network": _net("10.3.0.0/16", tgw_attachments=[_att("att-third", THIRD)])},
        HUB: {"access_network": hub_net, "access_assets": _assets("10.0.0.0/16", tgw_tables=tables)},
    })  # fmt: skip
    m = build_account_map(scan, OWN)
    links = _links(m, "tgw:tgw-1")
    assert links[("tgw:tgw-1", PEER)]["dir"] == "both"  # routes both ways
    assert ("tgw:tgw-1", THIRD) not in links  # attached, but its table routes nowhere: isolated
    assert any(to.startswith("onprem:vpn") for _, to in links)
    tgw = next(n for n in m["nodes"] if n["id"] == "tgw:tgw-1")
    assert "blackhole routes in its table" in tgw["flags"]
    assert not any(n["id"].startswith("members:") for n in m["nodes"])

    # The organisation view follows the same tables: account to account, no hub, THIRD isolated.
    r = build_access(scan)
    tgw_edges = {(e["from"], e["to"]) for e in r["edges"] if e["type"] == "tgw"}
    assert (OWN, PEER) in tgw_edges and (PEER, OWN) in tgw_edges
    assert not any(THIRD in pair for pair in tgw_edges)
    assert not any(n["id"].startswith("tgw:") for n in r["nodes"])


def test_routing_not_read_folds_the_members_and_says_so():
    scan = _scan({
        OWN: {"access_network": _net("10.1.0.0/16", tgw_attachments=[_att("att-own", OWN)]),
              "access_assets": _assets("10.1.0.0/16")},
        PEER: {"access_network": _net("10.2.0.0/16", tgw_attachments=[_att("att-peer", PEER)])},
    })  # fmt: skip
    m = build_account_map(scan, OWN)
    group = next(n for n in m["nodes"] if n["id"] == "members:tgw-1")
    assert group["kind"] == "group" and any(PEER in i for i in group["items"])
    assert _links(m)[("tgw:tgw-1", "members:tgw-1")]["assumed"] is True
    assert "routing not read" in next(n for n in m["nodes"] if n["id"] == "tgw:tgw-1")["flags"][0]


def test_peering_vpn_endpoints_privatelink_and_iam():
    peering = {"id": "pcx-1", "requester": OWN, "accepter": PEER, "requester_cidrs": ["10.1.0.0/16"],
               "accepter_cidrs": ["10.2.0.0/16"]}  # fmt: skip
    net = _net("10.1.0.0/16", peerings=[peering],
               endpoints=[{"id": "vpce-x", "service": "com.amazonaws.vpce.eu-west-1.vpce-svc-ext", "vpc": "vpc-1"}],
               services=[{"id": "vpce-svc-1", "name": "svc", "acceptance": False,
                          "allowed": [f"arn:aws:iam::{VENDOR}:root", "*"]}])  # fmt: skip
    assets = _assets("10.1.0.0/16",
                     routes=[{"id": "rtb-a", "vpc": "vpc-1", "main": True, "subnets": 1, "routes": [
                         {"dst": "10.2.0.0/16", "kind": "pcx", "target": "pcx-1", "blackhole": False}]}],
                     vgws=[{"id": "vgw-1", "vpcs": ["vpc-1"]}],
                     vpns=[{"id": "vpn-1", "gateway": "vgw-1", "customer_ip": "196.1.1.1", "name": "DC",
                            "tunnels": 2, "up": 1}],
                     aws_endpoints=[{"id": "vpce-s3", "service": "s3", "vpc": "vpc-1", "type": "Gateway",
                                     "open_policy": True}])  # fmt: skip
    scan = _scan({OWN: {"access_network": net, "access_assets": assets,
                        "access_trusts": [{"role": "vendor", "kind": "account", "id": VENDOR, "external_id": True}],
                        "buckets": [{"name": "b", "grants": [{"kind": "anyone", "id": "*",
                                                              "actions": ["s3:GetObject"]}]}]},
                  PEER: {"access_network": _net("10.2.0.0/16")}})  # fmt: skip
    m = build_account_map(scan, OWN)
    links = _links(m)
    assert links[("vpc:vpc-1", "pcx-1")] and links[("pcx-1", PEER)]["dir"] == "both"
    assert links[("vgw-1", "onprem:196.1.1.1")]["dir"] == "both"
    assert "1 of 2 tunnels up" in " ".join(links[("vgw-1", "onprem:196.1.1.1")]["details"])
    assert links[("vpce:vpc-1", "aws")]["dir"] == "out"
    assert "policy allows everything" in next(n for n in m["nodes"] if n["id"] == "vpce:vpc-1")["items"][0]
    assert ("vpce-x", "svc:com.amazonaws.vpce.eu-west-1.vpce-svc-ext") in links  # provider outside the scan
    assert links[("vpce-svc-1", VENDOR)]["dir"] == "in" and ("vpce-svc-1", "anyone") in links
    assert "connections accepted automatically" in next(n for n in m["nodes"] if n["id"] == "vpce-svc-1")["flags"]
    assert links[("iam:roles", VENDOR)]["dir"] == "in" and ("iam:buckets", "anyone") in links
    peer = next(n for n in m["nodes"] if n["id"] == PEER)
    assert peer["pivot"] is True  # scanned: its map can be opened


def test_flows_are_placed_by_the_local_subnets_route():
    routes = [{"id": "rtb-a", "vpc": "vpc-1", "main": True, "subnets": 1, "routes": [
        {"dst": "0.0.0.0/0", "kind": "nat", "target": "nat-1", "blackhole": False},
        {"dst": "10.0.0.0/8", "kind": "tgw", "target": "tgw-1", "blackhole": False}]}]  # fmt: skip
    assets = _assets("10.1.0.0/16", routes=routes, igws=[{"id": "igw-1", "vpc": "vpc-1"}],
                     nats=[{"id": "nat-1", "vpc": "vpc-1", "type": "public", "private_ip": "10.1.0.5"}])  # fmt: skip
    rows = [
        {"src": "10.1.1.9", "dst": "10.2.0.7", "port": "5432", "bytes": 5000, "flows": 4},  # to PEER via the TGW
        {"src": "10.2.0.7", "dst": "10.1.1.9", "port": "8443", "bytes": 700, "flows": 1},  # from PEER
        {"src": "10.1.0.5", "dst": "151.101.1.69", "port": "443", "bytes": 9000, "flows": 2},  # the NAT itself
        {"src": "10.1.1.9", "dst": "10.1.1.10", "port": "6379", "bytes": 100, "flows": 1},  # inside
        {"src": "10.1.200.1", "dst": "8.8.8.8", "port": "53", "bytes": 30, "flows": 1},  # no subnet known
    ]
    flows = {"eu-west-1": {"hours": 24, "rows": rows, "total_bytes": 20000, "covered": ["vpc-1"], "s3_only": []}}
    scan = _scan({
        OWN: {"access_network": _net("10.1.0.0/16", tgw_attachments=[_att("att-own", OWN)]), "access_assets": assets,
              "access_flows": flows},
        PEER: {"access_network": _net("10.2.0.0/16", tgw_attachments=[_att("att-peer", PEER)])},
    })  # fmt: skip
    m = build_account_map(scan, OWN)
    links = _links(m)
    via_tgw = links[("tgw:tgw-1", PEER)]
    assert (via_tgw["bytes_out"], via_tgw["bytes_in"], via_tgw["observed"]) == (5000, 700, True)
    assert links[("nat-1", "internet")]["bytes_out"] == 9000
    assert links[("igw-1", "internet")]["observed"] is False  # covered by flow logs, carried nothing
    assert links[("tgw:tgw-1", "members:tgw-1")]["observed"] is False
    f = m["flows"]
    assert (f["attributed_bytes"], f["internal_bytes"], f["unplaced_bytes"]) == (14700, 100, 30)
    assert f["top"][0]["id"] == "internet" and f["covered_vpcs"] == ["vpc-1"]


def test_not_available_without_the_facts_and_falls_back_to_the_first_account():
    assert build_account_map({"assurance": {}})["available"] is False
    old = _scan({OWN: {"access_network": _net("10.1.0.0/16")}})
    assert "before the account map existed" in build_account_map(old)["reason"]
    scan = _scan({OWN: {"access_assets": _assets("10.1.0.0/16")}})
    m = build_account_map(scan, "999999999999")
    assert m["available"] and m["account"]["id"] == OWN and m["flows"] == {"read": False}


def test_demo_has_maps_flows_and_read_routing():
    scan = build_demo_scan()
    ids = {a["name"]: a["id"] for a in scan["accounts"]}
    digital = build_account_map(scan, ids["digital-channels-prod"])
    kinds = {n["kind"] for n in digital["nodes"]}
    assert {"igw", "nat", "tgw", "lb", "api", "cloudfront", "vpce", "role"} <= kinds
    assert digital["flows"]["read"] and digital["flows"]["attributed_bytes"] > 0
    dev = build_account_map(scan, ids["data-platform-dev"])
    assert not any(n["id"].startswith("members:") for n in dev["nodes"])  # the non-production tables are read
    legacy = build_account_map(scan, ids["legacy-batch-prod"])
    assert {"vgw", "public-ip", "transfer", "pcx"} <= {n["kind"] for n in legacy["nodes"]}


def test_human_bytes():
    assert human_bytes(512) == "512 B" and human_bytes(2048) == "2.0 KB" and human_bytes(3 * 1024**3) == "3.0 GB"


def test_map_endpoint():
    c = client()
    sid = c.post("/api/scans/demo", headers=H).json()["id"]
    r = c.post("/api/access/map", json={"scan_id": sid}, headers=H)
    assert r.status_code == 200 and r.json()["available"]
    assert c.post("/api/access/map", json={"scan_id": sid, "account": "nope"}, headers=H).status_code == 422
    assert c.post("/api/access/map", json={"scan_id": "missing"}, headers=H).status_code == 404
