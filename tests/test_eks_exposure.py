"""Kubernetes exposure: actuators on the traffic port, catch-all Ingress routes, namespaces no network policy
covers, secrets written into workload specs, and nodes whose metadata answers their pods."""

import exitrisk.collectors.assurance as checks
from exitrisk import assurance
from exitrisk.collectors.outage import K8sRefused, K8sUnreachable, read_exposure, read_workloads
from tests.test_assurance import FakeClient, _ctx


def _deploy(ns, name, labels, containers):
    template = {"metadata": {"labels": labels}, "spec": {"containers": containers}}
    return {"metadata": {"namespace": ns, "name": name}, "spec": {"replicas": 3, "template": template}}


def _probe(path, port):
    return {"httpGet": {"path": path, "port": port}}


def _cluster(objects):
    def list_items(path, cap):
        if path in objects:
            got = objects[path]
            if isinstance(got, Exception):
                raise got
            return got
        if (
            path.startswith("/apis/apps")
            or path.startswith("/apis/autoscaling")
            or path in ("/api/v1/pods", "/apis/policy/v1/poddisruptionbudgets")
        ):
            return []
        raise K8sUnreachable("HTTP 404")

    return list_items


GATEWAY = _deploy("edge", "gateway", {"app": "gateway"}, [{
    "name": "app", "ports": [{"name": "http", "containerPort": 8080}],
    "livenessProbe": _probe("/actuator/health/liveness", "http"),
    "env": [{"name": "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "value": "health,loggers,env,refresh"},
            {"name": "CLIENT_SECRET", "value": "s3cr3t-value-123"},
            {"name": "DB_PASSWORD_FILE", "value": "/run/secrets/db-password"},
            {"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "k", "key": "v"}}},
            {"name": "TOKEN_URL", "value": "https://idp.example.com/token"},
            {"name": "DB_PASSWORD", "value": "${DB_PASS_FROM_VAULT}"}],
}])  # fmt: skip
SEPARATE = _deploy("apps", "billing", {"app": "billing"}, [{
    "name": "app", "ports": [{"containerPort": 8080}, {"containerPort": 8081}],
    "readinessProbe": _probe("/actuator/health/readiness", 8081),
}])  # fmt: skip
INTERNAL = _deploy("apps", "ledger", {"app": "ledger"}, [{
    "name": "app", "readinessProbe": _probe("/actuator/health", 8080),
}])  # fmt: skip
SERVICES = [
    {"metadata": {"namespace": "edge", "name": "gateway"},
     "spec": {"selector": {"app": "gateway"}, "ports": [{"port": 80, "targetPort": "http"}]}},
    {"metadata": {"namespace": "apps", "name": "billing"},
     "spec": {"selector": {"app": "billing"}, "ports": [{"port": 80, "targetPort": 8080}]}},
    {"metadata": {"namespace": "apps", "name": "ledger"},
     "spec": {"selector": {"app": "ledger"}, "ports": [{"port": 8080}]}},
]  # fmt: skip
INGRESSES = [
    {"metadata": {"namespace": "edge", "name": "public"}, "spec": {"rules": [{"host": "app.example.com", "http": {
        "paths": [{"path": "/api(/|$)(.*)", "backend": {"service": {"name": "gateway", "port": {"number": 80}}}}]}}]}},
    {"metadata": {"namespace": "apps", "name": "ledger"}, "spec": {"rules": [{"host": "ledger.example.com", "http": {
        "paths": [{"path": "/ledger/v1", "backend": {"service": {"name": "ledger", "port": {"number": 8080}}}}]}}]}},
]  # fmt: skip


def _read(extra=None):
    objects = {"/apis/apps/v1/deployments": [GATEWAY, SEPARATE, INTERNAL], "/api/v1/services": SERVICES,
               "/apis/networking.k8s.io/v1/ingresses": INGRESSES,
               "/apis/networking.k8s.io/v1/networkpolicies": [{"metadata": {"namespace": "apps"}}],
               **(extra or {})}  # fmt: skip
    read = _cluster(objects)
    got = read_workloads(read)
    return got["workloads"], read_exposure(read, got["workloads"])


def test_actuator_on_the_traffic_port_and_whether_an_ingress_sends_every_path_there():
    workloads, _ = _read()
    by = {w["name"]: w for w in workloads}
    gw = by["gateway"]["actuator"]
    assert gw["port"] == 8080 and gw["service"] == "gateway" and "app.example.com/api(/|$)(.*)" in gw["routes"][0]
    assert by["gateway"]["mgmt_expose"] == "health,loggers,env,refresh"
    assert "actuator" not in by["billing"]  # the actuator has its own port, which the Service does not serve
    assert by["ledger"]["actuator"]["routes"] == []  # served on the traffic port; its Ingress names one path only
    assert not any(k.startswith("_") for w in workloads for k in w if k in ("_actuator", "_labels", "_ports"))


def test_secret_env_names_literals_only_never_their_values():
    workloads, _ = _read()
    gw = next(w for w in workloads if w["name"] == "gateway")
    assert gw["secret_env"] == ["app/CLIENT_SECRET"]
    assert "s3cr3t" not in repr(workloads)


def test_namespaces_no_policy_covers_and_a_cluster_wide_policy_leaves_them_unjudged():
    _, got = _read()
    assert got["policy_access"] == "read" and got["open_namespaces"] == ["edge"]
    _, got = _read({"/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies": [{"metadata": {"name": "deny"}}]})
    assert got["policy_access"] == "cluster-wide policies" and got["open_namespaces"] == []
    _, got = _read({"/apis/networking.k8s.io/v1/networkpolicies": K8sRefused("403")})
    assert got["policy_access"] == "refused: networking.k8s.io" and got["open_namespaces"] == []


def test_assurance_judges_the_clusters_the_eks_read_saw():
    workloads, exposure = _read()
    cluster = {"name": "c1", "region": "eu-west-1", "access": "read", "workloads": workloads, **exposure}
    cluster["open_namespaces"] = [*cluster["open_namespaces"], "kube-system"]
    ax = assurance._Account({})
    assurance._eks_exposure(ax, {"clusters": [cluster]})
    c = ax.checks
    assert c["eks_actuator_exposed"]["status"] == "fail" and "c1/edge/gateway" in c["eks_actuator_exposed"]["ev"][0]
    assert "loggers" in c["eks_actuator_exposed"]["ev"][0]
    assert c["eks_actuator_traffic_port"]["ev"] == [
        "c1/apps/ledger: /actuator/health on port 8080, which Service ledger serves"
    ]
    assert c["eks_no_network_policy"]["ev"] == ["c1/edge"]  # kube-system is the platform's
    assert c["eks_literal_secrets"]["ev"] == ["c1/edge/gateway: app/CLIENT_SECRET"]


def test_assurance_says_why_it_could_not_judge():
    ax = assurance._Account({})
    assurance._eks_exposure(ax, None)
    assert ax.checks["eks_actuator_exposed"]["status"] == "unknown"
    assert "Outage Risk Report" in ax.checks["eks_actuator_exposed"]["note"]
    assurance._eks_exposure(ax, {"clusters": []})
    assert ax.checks["eks_literal_secrets"]["status"] == "na"
    old = {"name": "c1", "region": "r", "access": "read", "workloads": [{"ns": "a", "name": "b"}]}  # an older scan
    assurance._eks_exposure(ax, {"clusters": [old]})
    assert ax.checks["eks_literal_secrets"]["status"] == "unknown"  # not read is never a pass
    assert ax.checks["eks_no_network_policy"]["status"] == "unknown"


def test_nodes_whose_metadata_answers_two_hops_away():
    ec2 = FakeClient({
        "describe_security_groups": {"SecurityGroups": []},
        "describe_network_interfaces": {"NetworkInterfaces": []},
        "describe_network_acls": {"NetworkAcls": []},
        "describe_instances": {"Reservations": [{"Instances": [
            {"InstanceId": "i-node", "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 2},
             "Tags": [{"Key": "eks:nodegroup-name", "Value": "ng"}], "ImageId": "ami-1"},
            {"InstanceId": "i-karp", "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1},
             "Tags": [{"Key": "karpenter.sh/nodepool", "Value": "default"}], "ImageId": "ami-1"},
            {"InstanceId": "i-web", "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 2},
             "ImageId": "ami-1"}]}]},
        "describe_images": {"Images": []},
    })  # fmt: skip
    ctx = _ctx({"ec2": ec2})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "ec2-network"), "eu-west-1")
    out = ctx.r.finish()
    assert out["eks_node_imds_pods"]["status"] == "fail"
    assert out["eks_node_imds_pods"]["ev"] == ["i-node hop limit 2 (eu-west-1)"]  # a server that is not a node: no


def test_a_policy_engine_installed_but_unreadable_leaves_the_namespaces_unjudged():
    workloads = [{"ns": "edge", "name": "gateway"}]
    objects = {"/api/v1/services": [], "/apis/networking.k8s.io/v1/ingresses": [],
               "/apis/networking.k8s.io/v1/networkpolicies": [],
               "/apis/cilium.io/v2/ciliumnetworkpolicies": K8sRefused("403"),
               "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies": K8sRefused("403"),
               "/apis/crd.projectcalico.org/v1/networkpolicies": K8sRefused("403")}  # fmt: skip
    read = _cluster(objects)
    got = read_exposure(read, workloads, {"networking.k8s.io", "cilium.io"})
    assert got["policy_access"] == "refused: cilium.io" and got["open_namespaces"] == []
    got = read_exposure(read, workloads, {"networking.k8s.io"})  # neither engine installed: its 403s are not asked
    assert got["policy_access"] == "read" and got["open_namespaces"] == ["edge"]
