"""Cloud Assurance, PrivateLink and Network Load Balancers: who may connect to an endpoint service, whether the
NLB in front filters anything, and how open the account's own VPC endpoints are."""

import json

from test_assurance import FakeClient, _ctx

import exitrisk.collectors.assurance as checks
from exitrisk import assurance
from exitrisk.resilience import _patterns

DEFAULT_POLICY = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]})
ORG_POLICY = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*",
                                        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]})  # fmt: skip
OPEN_443 = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
VPC_443 = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}


def _run(services=(), perms=None, nlbs=(), endpoints=(), groups=()):
    ec2 = FakeClient({
        "describe_vpc_endpoint_service_configurations": {"ServiceConfigurations": list(services)},
        "describe_vpc_endpoint_service_permissions":
            lambda ServiceId, **_: {"AllowedPrincipals": [{"Principal": p} for p in (perms or {}).get(ServiceId, [])]},
        "describe_vpc_endpoints": {"VpcEndpoints": list(endpoints)},
        "describe_security_groups": {"SecurityGroups": list(groups)},
    })  # fmt: skip
    v2 = FakeClient({"describe_load_balancers": {"LoadBalancers": list(nlbs)}})
    ctx = _ctx({"ec2": ec2, "elbv2": v2})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "privatelink"), "eu-west-1")
    out = ctx.r.finish()
    return {cid: (c["ev"] if c["status"] == "fail" else []) for cid, c in out.items()} | {"_raw": out}


def _svc(sid="vpce-svc-1", acceptance=False, nlb="arn:nlb/1"):
    return {"ServiceId": sid, "ServiceName": f"com.amazonaws.vpce.eu-west-1.{sid}", "ServiceState": "Available",
            "AcceptanceRequired": acceptance, "NetworkLoadBalancerArns": [nlb]}  # fmt: skip


def _nlb(arn="arn:nlb/1", scheme="internal", groups=(), enforce=None):
    lb = {"LoadBalancerArn": arn, "LoadBalancerName": arn.split("/")[-1], "Type": "network", "Scheme": scheme,
          "SecurityGroups": list(groups)}  # fmt: skip
    if enforce:
        lb["EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic"] = enforce
    return lb


def test_a_service_any_account_can_join_without_approval_fails():
    out = _run(services=[_svc()], perms={"vpce-svc-1": ["*"]}, nlbs=[_nlb(groups=["sg-1"], enforce="on")])
    assert out["vpce_service_open"] and "any AWS account" in out["vpce_service_open"][0]


def test_a_service_named_accounts_or_approval_passes():
    out = _run(services=[_svc(), _svc("vpce-svc-2", acceptance=True, nlb="arn:nlb/2")],
               perms={"vpce-svc-1": ["arn:aws:iam::222222222222:root"], "vpce-svc-2": ["*"]},
               nlbs=[_nlb(groups=["sg-1"], enforce="on"),
                     _nlb("arn:nlb/2", groups=["sg-1"], enforce="on")])  # fmt: skip
    assert not out["vpce_service_open"]
    assert not out["nlb_unfiltered"]


def test_an_nlb_behind_privatelink_without_a_group_or_enforcement_fails():
    out = _run(services=[_svc(), _svc("vpce-svc-2", nlb="arn:nlb/2")],
               nlbs=[_nlb(), _nlb("arn:nlb/2", groups=["sg-1"], enforce="off")])  # fmt: skip
    got = out["nlb_unfiltered"]
    assert len(got) == 2
    assert "no security group" in got[0] and "not applied to PrivateLink traffic" in got[1]


def test_internet_facing_nlb_without_a_group_fails_internal_one_passes():
    out = _run(nlbs=[_nlb("arn:nlb/pub", scheme="internet-facing"), _nlb("arn:nlb/int")])
    assert out["nlb_unfiltered"] == ["pub: internet-facing with no security group (eu-west-1)"]


def test_endpoint_groups_open_to_any_address_fail():
    eps = [{"VpcEndpointId": "vpce-1", "VpcEndpointType": "Interface", "State": "available",
            "ServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-9", "Groups": [{"GroupId": "sg-open"}]},
           {"VpcEndpointId": "vpce-2", "VpcEndpointType": "Interface", "State": "available",
            "ServiceName": "com.amazonaws.eu-west-1.sts", "Groups": [{"GroupId": "sg-vpc"}],
            "PolicyDocument": ORG_POLICY}]  # fmt: skip
    groups = [{"GroupId": "sg-open", "IpPermissions": [OPEN_443]}, {"GroupId": "sg-vpc", "IpPermissions": [VPC_443]}]
    out = _run(endpoints=eps, groups=groups)
    assert out["vpce_sg_open"] == [
        "vpce-1 com.amazonaws.vpce.eu-west-1.vpce-svc-9: sg-open allows tcp 443 from any address (eu-west-1)"
    ]
    assert not out["vpce_policy_open"]


def test_the_default_full_access_policy_fails_only_for_aws_services():
    eps = [{"VpcEndpointId": "vpce-s3", "VpcEndpointType": "Gateway", "State": "available",
            "ServiceName": "com.amazonaws.eu-west-1.s3", "PolicyDocument": DEFAULT_POLICY},
           {"VpcEndpointId": "vpce-own", "VpcEndpointType": "Interface", "State": "available",
            "ServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-9", "PolicyDocument": DEFAULT_POLICY}]  # fmt: skip
    out = _run(endpoints=eps)
    assert out["vpce_policy_open"] == ["vpce-s3 com.amazonaws.eu-west-1.s3 (eu-west-1)"]


def test_full_access_reading():
    assert checks._full_access(DEFAULT_POLICY)
    assert checks._full_access({"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": ["*"],
                                              "Resource": "*"}})  # fmt: skip
    assert not checks._full_access(ORG_POLICY)
    assert not checks._full_access({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                   "Resource": "*"}]})  # fmt: skip
    assert not checks._full_access("not json")
    assert not checks._full_access(None)


# ---------------------------------------------------------------------------------- paths from the edge


def test_the_collector_records_the_edge_paths():
    ec2 = FakeClient({
        "describe_vpc_endpoint_service_configurations": {"ServiceConfigurations": [_svc()]},
        "describe_vpc_endpoint_service_permissions": {"AllowedPrincipals": []},
        "describe_vpc_endpoints": {"VpcEndpoints": [
            {"VpcEndpointId": "vpce-1", "VpcEndpointType": "Interface", "State": "available",
             "ServiceName": "com.amazonaws.vpce.eu-west-1.vpce-svc-9", "Groups": []}]},
        "describe_security_groups": {"SecurityGroups": [{"GroupId": "sg-open", "IpPermissions": [OPEN_443]}]},
        "describe_network_interfaces": {"NetworkInterfaces": [
            {"Description": "ELB app/web/abc", "PrivateIpAddress": "10.1.0.9", "Groups": [{"GroupId": "sg-open"}]},
            {"Description": "ELB net/1/abc", "PrivateIpAddress": "10.1.0.8", "Groups": []},
            {"Description": "VPC Endpoint Interface vpce-1", "PrivateIpAddress": "10.1.0.7", "Groups": []}]},
        "describe_vpcs": {"Vpcs": [{"CidrBlock": "10.1.0.0/16",
                                    "CidrBlockAssociationSet": [{"CidrBlock": "10.1.0.0/16"}]}]},
    })  # fmt: skip
    v2 = FakeClient({
        "describe_load_balancers": {"LoadBalancers": [_nlb(), {"LoadBalancerArn": "arn:alb/pub",
                                     "LoadBalancerName": "pub", "Type": "application", "Scheme": "internet-facing"}]},
        "describe_target_groups": {"TargetGroups": [{"TargetGroupArn": "tg", "TargetType": "ip",
                                                     "LoadBalancerArns": ["arn:alb/pub"]}]},
        "describe_target_health": {"TargetHealthDescriptions": [{"Target": {"Id": "10.2.0.5"}}]},
    })  # fmt: skip
    ctx = _ctx({"ec2": ec2, "elbv2": v2})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "privatelink"), "eu-west-1")
    got = ctx.r.facts["edge_paths"]["eu-west-1"]
    assert got["services"] == [{"id": "vpce-svc-1", "name": "com.amazonaws.vpce.eu-west-1.vpce-svc-1", "lb": "1",
                                "filter": "none", "open": False}]  # fmt: skip
    assert got["lb_ips"]["10.1.0.9"] == {"lb": "web", "type": "application", "filter": "group", "open": True}
    assert got["endpoints"] == [{"id": "vpce-1", "service": "com.amazonaws.vpce.eu-west-1.vpce-svc-9",
                                 "ips": ["10.1.0.7"]}]  # fmt: skip
    assert got["ip_targets"] == [{"lb": "pub", "public": True, "ips": ["10.2.0.5"]}]
    assert got["cidrs"] == ["10.1.0.0/16"] and not got["partial"]


def _paths(services=(), endpoints=(), lb_ips=None, ip_targets=(), cidrs=()):
    return {"eu-west-1": {"services": list(services), "endpoints": list(endpoints), "lb_ips": lb_ips or {},
                          "ip_targets": list(ip_targets), "cidrs": list(cidrs), "partial": False}}  # fmt: skip


def _judge(accounts: dict, edge="edge"):
    """{account name: (status, evidence)} for edge_reached_unfiltered, from {name: edge_paths facts}."""
    listed = [{"id": str(i), "name": n} for i, n in enumerate(accounts)]
    checked = {x["id"]: {"checks": {}, "facts": {"edge_paths": accounts[x["name"]]} if accounts[x["name"]] else {}}
               for x in listed}  # fmt: skip
    reached, services, owners, unread = assurance._edge_sources(checked, listed, _patterns(edge))
    out = {}
    for x in listed:
        ax = assurance._Account(checked[x["id"]])
        assurance._edge_reached(ax, x["id"], reached, services, owners, unread, bool(reached or services))
        c = ax.checks["edge_reached_unfiltered"]
        out[x["name"]] = (c["status"], c.get("ev", []), c["note"])
    return out


SVC = "com.amazonaws.vpce.eu-west-1.vpce-svc-1"


def test_a_privatelink_service_consumed_from_the_edge_account_must_filter():
    out = _judge({
        "net-edge": _paths(endpoints=[{"id": "vpce-e", "service": SVC, "ips": []}], cidrs=["10.0.0.0/16"]),
        "payments": _paths(services=[{"id": "vpce-svc-1", "name": SVC, "lb": "pay-nlb", "filter": "none",
                                      "open": False}], cidrs=["10.1.0.0/16"]),
        "cards": _paths(services=[{"id": "vpce-svc-2", "name": SVC.replace("1", "2"), "lb": "card-nlb",
                                   "filter": "none", "open": False}], cidrs=["10.2.0.0/16"]),
    })  # fmt: skip
    status, ev, _ = out["payments"]
    assert status == "fail" and ev[0].startswith(
        "pay-nlb behind PrivateLink service vpce-svc-1 (eu-west-1): no "
        "security group; reached from endpoint vpce-e in edge account"
    )
    assert out["cards"][0] == "pass"  # not consumed from the edge


def test_a_filtered_service_passes():
    out = _judge({
        "net-edge": _paths(endpoints=[{"id": "vpce-e", "service": SVC, "ips": []}]),
        "payments": _paths(services=[{"id": "vpce-svc-1", "name": SVC, "lb": "pay-nlb", "filter": "group",
                                      "open": False}]),
    })  # fmt: skip
    assert out["payments"][0] == "pass"


def test_an_internet_facing_lb_into_an_endpoint_marks_the_service_reached_without_naming_the_edge():
    out = _judge({
        "shared-ingress": _paths(ip_targets=[{"lb": "public-alb", "public": True, "ips": ["10.0.0.7"]}],
                                 endpoints=[{"id": "vpce-e", "service": SVC, "ips": ["10.0.0.7"]}],
                                 cidrs=["10.0.0.0/16"]),
        "payments": _paths(services=[{"id": "vpce-svc-1", "name": SVC, "lb": "pay-nlb", "filter": "not applied",
                                      "open": False}], cidrs=["10.1.0.0/16"]),
    }, edge="nothing-matches")  # fmt: skip
    status, ev, _ = out["payments"]
    assert status == "fail" and "not applied to PrivateLink traffic" in ev[0]
    assert "public-alb in shared-ingress (eu-west-1, internet-facing)" in ev[0]


def test_a_load_balancer_targeted_across_the_transit_gateway():
    out = _judge({
        "net-edge": _paths(ip_targets=[{"lb": "edge-nlb", "public": False, "ips": ["10.1.0.5", "10.9.0.5"]}],
                           cidrs=["10.0.0.0/16"]),
        "payments": _paths(lb_ips={"10.1.0.5": {"lb": "pay-alb", "type": "application", "filter": "group",
                                                "open": True}}, cidrs=["10.1.0.0/16"]),
        # the same range in two accounts: whose address it is cannot be told, so neither is judged on it
        "lab-a": _paths(lb_ips={"10.9.0.5": {"lb": "a", "type": "network", "filter": "none", "open": False}},
                        cidrs=["10.9.0.0/16"]),
        "lab-b": _paths(lb_ips={"10.9.0.5": {"lb": "b", "type": "network", "filter": "none", "open": False}},
                        cidrs=["10.9.0.0/16"]),
    })  # fmt: skip
    status, ev, _ = out["payments"]
    assert status == "fail" and ev == ["pay-alb (application load balancer, eu-west-1): its security group allows "
                                       "any address; reached from edge-nlb in net-edge (eu-west-1)"]  # fmt: skip
    assert out["lab-a"][0] == "pass" and out["lab-b"][0] == "pass"


def test_no_edge_in_the_scan_or_an_old_scan_is_unknown():
    out = _judge({"payments": _paths(cidrs=["10.1.0.0/16"]), "old": None})
    assert out["payments"][0] == "unknown" and "no path from the internet edge" in out["payments"][2]
    assert out["old"] == ("unknown", [], "needs a new scan")
