"""Cloud Assurance, PrivateLink and Network Load Balancers: who may connect to an endpoint service, whether the
NLB in front filters anything, and how open the account's own VPC endpoints are."""

import json

from test_assurance import FakeClient, _ctx

import exitrisk.collectors.assurance as checks

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
