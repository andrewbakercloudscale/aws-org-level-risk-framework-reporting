"""The Outage Risk Report: how a measure is judged, what the collector reads, and the report built on it."""

import base64
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import boto3
import pytest
from botocore.exceptions import ClientError

from exitrisk.collectors import outage as collector
from exitrisk.demo import build_demo_scan
from exitrisk.filtering import AccountFilter
from exitrisk.outage import (
    OutageAnswers,
    _node_view,
    black_friday,
    build_outage,
    catalog,
    findings_csv,
    judge_burstable,
    judge_capacity,
    workload_rows,
)


@pytest.fixture(scope="module")
def scan():
    return build_demo_scan(6)


@pytest.fixture(scope="module")
def report(scan):
    return build_outage(scan)


def test_black_friday_is_the_day_after_the_fourth_thursday_of_november():
    assert black_friday(date(2026, 11, 1)) == date(2026, 11, 27)
    assert black_friday(date(2024, 11, 1)) == date(2024, 11, 29)
    assert black_friday(date(2026, 11, 28)) == date(2027, 11, 26)


def _sev(pct=50.0, load=False, days=None):
    row = {"pct": pct, "load": load}
    if days is not None:
        row["days"] = days
    return judge_capacity(row, OutageAnswers(), 26)[0]


def test_capacity_is_judged_on_now_on_the_peak_and_on_running_out():
    assert _sev(91.0) == "critical"
    assert _sev(60.0, load=True) == "high"  # 120% at twice the load
    assert _sev(60.0) is None  # a store does not grow with traffic
    assert _sev(40.0, load=True) == "medium"
    assert _sev(20.0, load=True) is None
    assert _sev(days=10.0) == "critical"  # full before the peak
    assert _sev(days=40.0) == "high"  # full within a month after it


@pytest.mark.parametrize(("text", "want"), [("250m", 250), ("2", 2000), ("0.5", 500), ("", None), (None, None)])
def test_parse_cpu(text, want):
    assert collector.parse_cpu(text) == want


@pytest.mark.parametrize(("text", "want"), [("512Mi", 512), ("1Gi", 1024), ("1G", 954), ("1048576", 1), (None, None)])
def test_parse_mem(text, want):
    assert collector.parse_mem(text) == want


def test_days_until_and_slope():
    s = collector.Series()
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for h in range(96):
        s.add(start + timedelta(hours=h), 50.0 + h / 24)  # one point a day
    assert round(s.slope(), 3) == 1.0
    assert round(collector.days_until(s.last, 100.0, s.slope())) == 46
    assert collector.days_until(50.0, 100.0, 0.0) is None
    short = collector.Series()
    short.add(start, 1.0)
    assert short.slope() == 0.0


def test_pod_sizes_add_up_and_a_missing_limit_is_unknown():
    tmpl = {"spec": {"containers": [
        {"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}}},
        {"resources": {"requests": {"cpu": "50m", "memory": "64Mi"}}},
    ]}}  # fmt: skip
    assert collector._pod_sizes(tmpl) == {"cpu_req": 150, "cpu_lim": None, "mem_req": 128, "mem_lim": None}


def _lists():
    deploy = lambda name, n: {  # noqa: E731
        "metadata": {"namespace": "pay", "name": name},
        "spec": {"replicas": n, "template": {"spec": {"containers": [
            {"resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "64Mi"}}}
        ]}}},
    }  # fmt: skip
    return {
        "/apis/apps/v1/deployments": [deploy("api", 3), deploy("worker", 1), deploy("off", 0)],
        "/apis/apps/v1/statefulsets": [],
        "/apis/policy/v1/poddisruptionbudgets": [],
        "/apis/autoscaling/v2/horizontalpodautoscalers": [{
            "metadata": {"namespace": "pay", "name": "api"},
            "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "api"}, "maxReplicas": 4},
            "status": {"currentReplicas": 4},
        }],
        "/api/v1/pods": [
            {"metadata": {"namespace": "pay", "name": "worker-7c9d6f5b8-abcde",
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "worker-7c9d6f5b8"}]},
             "status": {"phase": "Running",
                        "containerStatuses": [{"lastState": {"terminated": {"reason": "OOMKilled"}}}]}},
            {"metadata": {"namespace": "pay", "name": "x"}, "status": {"phase": "Pending"}},
        ],
    }  # fmt: skip


def test_read_workloads_matches_autoscalers_and_ooms_to_their_workload():
    lists = _lists()
    got = collector.read_workloads(lambda path, cap: lists[path])
    rows = {w["name"]: w for w in got["workloads"]}
    assert set(rows) == {"api", "worker"}  # scaled to nothing is left alone
    assert rows["api"]["hpa_max"] == 4 and rows["api"]["current"] == 4 and rows["api"]["hpa_min"] == 1  # the default
    assert rows["worker"]["oom"] == 1 and "hpa_max" not in rows["worker"]
    assert got["pending"] == 1


def test_workload_rules_find_fixed_single_low_and_killed():
    lists = _lists()
    got = collector.read_workloads(lambda path, cap: lists[path])
    rows = workload_rows({"name": "c", "region": "eu-west-1", "access": "read", **got}, OutageAnswers())
    rules = {(r["rule"], r["res"].split("/")[-1]) for r in rows}
    assert ("eks_single_replica", "worker") in rules
    assert ("eks_hpa_max", "api") in rules
    assert ("eks_low_cpu", "worker") in rules
    assert ("eks_low_memory", "worker") in rules
    assert ("eks_oom", "worker") in rules
    assert ("eks_fixed_replicas", "api") not in rules  # it has an autoscaler


def test_production_workloads_under_3_replicas_are_flagged_by_their_quietest_count():
    w = lambda name, n, **kw: {"ns": "pay", "name": name, "kind": "Deployment", "replicas": n, **kw}  # noqa: E731
    cluster = {"name": "c", "region": "eu-west-1", "access": "read", "workloads": [
        w("fixed2", 2), w("fixed3", 3), w("hpa2", 5, hpa_max=10, hpa_min=2, hpa="hpa2"),
        w("hpa3", 3, hpa_max=10, hpa_min=3, hpa="hpa3"), w("old", 1, hpa_max=10, hpa="old"),
    ]}  # fmt: skip
    rows = workload_rows(cluster, OutageAnswers())
    few = {r["res"].split("/")[-1] for r in rows if r["rule"] == "eks_single_replica"}
    assert few == {"fixed2", "hpa2"}  # a scan that did not read the minimum is not guessed at
    assert {r["res"].split("/")[-1] for r in rows if r["rule"] == "eks_fixed_replicas"} == {"fixed3"}


def test_a_pod_pending_past_the_grace_is_counted_with_the_schedulers_reason():
    now = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
    pend = lambda name, minutes, **status: {  # noqa: E731
        "metadata": {"namespace": "pay", "name": name,
                     "creationTimestamp": (now - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")},
        "status": {"phase": "Pending", **status}}  # fmt: skip
    unscheduled = {"conditions": [{"type": "PodScheduled", "status": "False",
                                   "message": "0/6 nodes are available: 6 Insufficient cpu."}]}  # fmt: skip
    lists = _lists() | {"/api/v1/pods": [
        pend("new", 5, **unscheduled),  # a node is probably on its way
        pend("stuck", 40, **unscheduled),
        pend("pull", 20, containerStatuses=[{"name": "app", "state": {"waiting": {"reason": "ImagePullBackOff"}}}]),
    ]}  # fmt: skip
    got = collector.read_workloads(lambda path, cap: lists[path], now=now)
    assert got["pending"] == 2
    row = next(r for r in workload_rows({"name": "c", "region": "r", "access": "read", **got}, OutageAnswers())
               if r["rule"] == "eks_pending")  # fmt: skip
    assert "Insufficient cpu" in row["note"] and "ImagePullBackOff" in row["note"] and "pay/stuck" in row["note"]


def _placed(nodes_zone: dict, pods: list[tuple], volumes: list[tuple] = ()):
    """A cluster read with pods of workload "db" (replicas 2) on the named nodes, and volumes in zones."""
    pod = lambda name, node, claim=None: {  # noqa: E731
        "metadata": {"namespace": "pay", "name": name, "ownerReferences": [{"kind": "StatefulSet", "name": "db"}]},
        "spec": {"nodeName": node, "volumes": [{"persistentVolumeClaim": {"claimName": claim}}] if claim else []},
        "status": {"phase": "Running"}}  # fmt: skip
    lists = _lists() | {
        "/apis/apps/v1/statefulsets": [{"metadata": {"namespace": "pay", "name": "db"},
                                        "spec": {"replicas": 2, "template": {"spec": {"containers": [{}]}}}}],
        "/api/v1/pods": [pod(*p) for p in pods],
        "/api/v1/nodes": [{"metadata": {"name": n, "labels": {collector.ZONE_LABEL: z}}, "status": {}}
                          for n, z in nodes_zone.items()],
        "/api/v1/persistentvolumes": [
            {"metadata": {"labels": {collector.ZONE_LABEL: z}},
             "spec": {"csi": {"driver": "ebs.csi.aws.com"}, "claimRef": {"namespace": "pay", "name": c}}}
            for c, z in volumes],
    }  # fmt: skip
    read = lambda path, cap: lists[path]  # noqa: E731
    c = {"name": "c", "region": "r", "access": "read", **collector.read_workloads(read), **collector.read_nodes(read)}
    collector.place_workloads(c["workloads"], c.pop("_zones"), collector.read_volume_zones(read))
    return {r["rule"] for r in workload_rows(c, OutageAnswers()) if r["res"] == "c/pay/db"}


def test_replicas_and_volumes_in_one_zone_are_found_only_when_the_cluster_has_others():
    nodes = {"n1": "az-a", "n2": "az-a", "n3": "az-b"}
    together = _placed(nodes, [("db-0", "n1", "d0"), ("db-1", "n2", "d1")], [("d0", "az-a"), ("d1", "az-a")])
    assert {"eks_one_zone", "eks_volume_one_zone"} <= together
    spread = _placed(nodes, [("db-0", "n1", "d0"), ("db-1", "n3", "d1")], [("d0", "az-a"), ("d1", "az-b")])
    assert not {"eks_one_zone", "eks_volume_one_zone"} & spread
    one_zone_cluster = _placed({"n1": "az-a", "n2": "az-a"}, [("db-0", "n1"), ("db-1", "n2")])
    assert "eks_one_zone" not in one_zone_cluster  # nowhere else to go


def test_an_autoscaler_that_cannot_read_its_metric_or_scales_only_when_throttled_is_found():
    hpa = lambda name, target, cond: {  # noqa: E731
        "metadata": {"namespace": "pay", "name": name},
        "spec": {"scaleTargetRef": {"kind": "Deployment", "name": name}, "maxReplicas": 10,
                 "metrics": [{"type": "Resource", "resource": {"name": "cpu",
                                                               "target": {"averageUtilization": target}}}]},
        "status": {"currentReplicas": 2, "conditions": [cond]}}  # fmt: skip
    blind = {"type": "ScalingActive", "status": "False", "reason": "FailedGetResourceMetric", "message": "no metrics"}
    off = {"type": "ScalingActive", "status": "False", "reason": "ScalingDisabled"}
    deploy = lambda name: {"metadata": {"namespace": "pay", "name": name}, "spec": {"replicas": 2, "template": {  # noqa: E731
        "spec": {"containers": [{"resources": {"requests": {"cpu": "900m"}, "limits": {"cpu": "1"}}}]}}}}  # fmt: skip
    lists = _lists() | {
        "/apis/apps/v1/deployments": [deploy("blind"), deploy("late"), deploy("paused")],
        "/apis/autoscaling/v2/horizontalpodautoscalers": [hpa("blind", 50, blind), hpa("late", 100, {}),
                                                           hpa("paused", 100, off)],
    }  # fmt: skip
    got = collector.read_workloads(lambda path, cap: lists[path])
    rules = {(r["rule"], r["res"].split("/")[-1]) for r in workload_rows({"name": "c", "region": "r", **got},
                                                                         OutageAnswers())}  # fmt: skip
    assert ("eks_hpa_blind", "blind") in rules and ("eks_hpa_blind", "paused") not in rules
    assert ("eks_hpa_late", "late") in rules  # 100% of a 900m request is 90% of the 1-core limit
    assert ("eks_hpa_late", "blind") not in rules  # 50% of the request is 45% of the limit


@pytest.mark.parametrize(("kind", "spot", "want"), [
    ("m6i.large", False, "L-1216C47A"), ("m6i.large", True, "L-34B43A08"), ("g5.xlarge", False, "L-DB2E81BA"),
    ("inf2.xlarge", False, "L-1945791B"), ("x2idn.large", False, "L-7295265B"), ("u-6tb1.metal", False, "L-43DA4232"),
])  # fmt: skip
def test_an_instance_type_counts_against_its_class_vcpu_quota(kind, spot, want):
    assert collector.vcpu_quota_code(kind, spot) == want


def test_node_group_growth_is_judged_against_the_vcpu_quota_left_at_the_expected_peak():
    q = lambda ng, nodes, used: {"res": ng, "what": f"{nodes} x m6i.2xlarge", "vcpus": nodes * 8, "spot": False,  # noqa: E731
                                 "code": "L-1216C47A", "value": 1000, "used": used}  # fmt: skip
    c = {"name": "c", "region": "r",
         "nodegroup_quota": [q("fits", 10, 100), q("tight", 10, 900), q("blocked", 20, 900)],
         "nodepools": [{"pool": "default", "res": "cpu", "used": 60000, "limit": 100000}]}  # fmt: skip
    rows = {r["res"]: r for r in workload_rows(c, OutageAnswers(peak_multiplier=2.0))}
    assert "c/fits" not in rows  # 80 more of 900 left
    assert rows["c/tight"]["sev"] == "medium"  # 80 of 100 left
    assert rows["c/blocked"]["sev"] == "high" and "ask for 1,060" in rows["c/blocked"]["note"]
    pool = rows["c/default cpu"]
    assert (pool["used"], pool["limit"], pool["pct"], pool["load"]) == (60.0, 100.0, 60.0, True)
    assert "c/tight" not in {r["res"] for r in workload_rows(c, OutageAnswers(peak_multiplier=1.5))}


def test_keda_scalers_that_will_not_scale_and_nodepool_limits_are_read():
    so = lambda name, triggers, **kw: {"metadata": {"namespace": "pay", "name": name, **kw.get("meta", {})},  # noqa: E731
                                       "spec": {"scaleTargetRef": {"name": name}, "triggers": triggers,
                                                **kw.get("spec", {})}, "status": kw.get("status", {})}  # fmt: skip
    sqs, cpu = [{"type": "aws-sqs-queue"}], [{"type": "cpu"}]
    lists = {"/apis/keda.sh/v1alpha1/scaledobjects": [
        so("ok", sqs, spec={"fallback": {"replicas": 6, "failureThreshold": 3}}),
        so("cpu-only", cpu),
        so("no-fallback", sqs, spec={"fallback": None}),
        so("broken", cpu, status={"conditions": [{"type": "Ready", "status": "False", "message": "auth failed"}]}),
        so("paused", cpu, meta={"annotations": {"autoscaling.keda.sh/paused-replicas": "2"}}),
    ], "/apis/karpenter.sh/v1/nodepools": [
        {"metadata": {"name": "default"}, "spec": {"limits": {"cpu": "100", "memory": "400Gi"}},
         "status": {"resources": {"cpu": "60", "memory": "100Gi"}}},
        {"metadata": {"name": "unbounded"}, "spec": {}, "status": {"resources": {"cpu": "8"}}},
    ]}  # fmt: skip

    def read(path, cap):
        if path not in lists:
            raise collector.K8sUnreachable("HTTP 404")
        return lists[path]

    got = {k["name"]: k["issues"] for k in collector.read_keda(read)}
    assert set(got) == {"no-fallback", "broken", "paused"}
    assert "aws-sqs-queue" in got["no-fallback"][0] and got["broken"][0] == "not ready: auth failed"
    pools = collector.read_nodepools(read)
    assert [(p["res"], p["used"], p["limit"]) for p in pools] == [("cpu", 60000, 100000), ("memory", 102400, 409600)]
    rows = {r["res"]: r for r in workload_rows({"name": "c", "region": "r", "keda": collector.read_keda(read)},
                                               OutageAnswers())}  # fmt: skip
    assert rows["c/pay/broken"]["sev"] == "high" and rows["c/pay/paused"]["sev"] == "medium"


def test_prometheus_is_found_by_name_and_port_and_not_its_neighbours():
    svc = lambda ns, name, port, ip="10.0.0.1": {  # noqa: E731
        "metadata": {"namespace": ns, "name": name}, "spec": {"clusterIP": ip, "ports": [{"port": port}]}}  # fmt: skip
    got = collector.prometheus_services([
        svc("mon", "prometheus-operated", 9090, ip="None"),
        svc("mon", "kube-prometheus-alertmanager", 9093),
        svc("mon", "prometheus-node-exporter", 9100),
        svc("infinity", "infinity-prometheus", 9090),
        svc("web", "shop", 9090),
    ])  # fmt: skip
    assert got == [
        "/api/v1/namespaces/infinity/services/infinity-prometheus:9090/proxy",
        "/api/v1/namespaces/mon/services/prometheus-operated:9090/proxy",  # headless, tried last
    ]


def test_prometheus_figures_land_on_their_workload_and_make_findings():
    got = collector.read_workloads(lambda path, cap: _lists()[path])
    s = lambda pod, container, v: {"metric": {"namespace": "pay", "pod": pod, "container": container}, "value": [0, v]}  # noqa: E731
    answers = {
        "prometheus_tsdb_lowest": [{"metric": {}, "value": [0, "3.5"]}],  # Prometheus holds 3.5 days
        "cfs_throttled": [s("api-7c9d6f5b8-abcde", None, "300"), s("api-7c9d6f5b8-fghij", None, "100"),
                          s("api-7c9d6f5b8-abcde", "init", "900")],
        "cfs_periods": [s("api-7c9d6f5b8-abcde", None, "1000"), s("api-7c9d6f5b8-fghij", None, "1000"),
                        s("api-7c9d6f5b8-abcde", "init", "1000")],
        "working_set": [s("worker-7c9d6f5b8-abcde", None, str(60 * 2**20)),
                        s("worker-5f6d7c8b9-vwxyz", None, str(40 * 2**20))],
        "restarts": [s("worker-7c9d6f5b8-abcde", None, "2"), s("worker-5f6d7c8b9-vwxyz", None, "2")],
        "cpu_usage": [s("api-7c9d6f5b8-abcde", None, "0.25"), s("api-7c9d6f5b8-fghij", None, "0.4")],
        "horizontalpodautoscaler": [
            {"metric": {"namespace": "pay", "horizontalpodautoscaler": "api"}, "value": [0, "4"]}
        ],
    }  # fmt: skip

    def query(expr):
        return next(v for k, v in answers.items() if k in expr)

    seen = collector.read_prometheus(query, got["workloads"])
    assert seen["prom_days"] == 3.5 and seen["prom_missed"] == []
    rows = {w["name"]: w for w in got["workloads"]}
    # 400 of 2000 periods; the init one is not counted. The highest 5-minute CPU is the busiest pod's.
    assert rows["api"]["throttled"] == {"container": None, "pct": 20.0, "limit_m": None, "max_m": 400}
    assert rows["worker"]["mem_peak"] == {"container": None, "mib": 60, "limit": 64, "pct": 93.8}
    assert rows["worker"]["restarts"] == 4 and rows["api"]["hpa_peak"] == 4
    cluster = {"name": "c", "region": "eu-west-1", "access": "read", **got, **seen}
    found = {(r["rule"], r["res"].split("/")[-1]): r for r in workload_rows(cluster, OutageAnswers())}
    # 20% is medium on its own; the autoscaler has been at its maximum of 4, so more pods cannot help.
    throttled = found[("eks_cpu_throttled", "api")]
    assert throttled["sev"] == "high" and "maximum of 4" in throttled["note"]
    assert found[("eks_memory_pressure", "worker")]["pct"] == 93.8
    assert ("eks_restarts", "worker") in found
    # Container Insights already measures memory per pod: Prometheus's figure is not counted twice.
    found = {r["rule"] for r in workload_rows({**cluster, "insights": True}, OutageAnswers())}
    assert "eks_memory_pressure" not in found and "eks_cpu_throttled" in found


def test_a_prometheus_query_that_fails_leaves_only_its_figure_out():
    got = collector.read_workloads(lambda path, cap: _lists()[path])

    def query(expr):
        if "working_set" in expr:
            raise collector.K8sUnreachable("timed out")
        return []

    seen = collector.read_prometheus(query, got["workloads"])
    assert seen["prom_missed"] == ["memory"] and seen["prom_days"] == 7


def test_throttling_well_under_the_limit_at_its_busiest_is_told_apart_as_bursts():
    thr = lambda name, peak: {  # noqa: E731
        "ns": "pay", "name": name, "kind": "Deployment", "replicas": 2,
        "throttled": {"container": "app", "pct": 10.0, "limit_m": 1000, "max_m": peak}}  # fmt: skip
    cluster = {"name": "c", "region": "r", "prom_days": 7,
               "workloads": [thr("bursty", 300), thr("busy", 950), thr("unknown", None)]}  # fmt: skip
    found = {(r["rule"], r["res"].split("/")[-1]): r for r in workload_rows(cluster, OutageAnswers())}
    assert ("eks_cpu_bursts", "bursty") in found and ("eks_cpu_throttled", "bursty") not in found
    assert "300m of its 1000m limit" in found[("eks_cpu_bursts", "bursty")]["note"]
    assert ("eks_cpu_throttled", "busy") in found and ("eks_cpu_bursts", "busy") not in found
    assert ("eks_cpu_throttled", "unknown") in found  # no CPU peak read: it cannot be called bursts
    assert found[("eks_cpu_bursts", "bursty")]["sev"] == "medium"


def test_probes_that_restart_pods_under_load_or_before_they_start_are_found():
    http = lambda path, **kw: {"httpGet": {"path": path, "port": 8080}, **kw}  # noqa: E731
    deploy = lambda name, **probes: {"metadata": {"namespace": "pay", "name": name}, "spec": {"replicas": 2,  # noqa: E731
        "template": {"spec": {"containers": [{"name": "app", **probes}]}}}}  # fmt: skip
    slow = {"readinessProbe": http("/ready"),
            "livenessProbe": http("/live", timeoutSeconds=5, initialDelaySeconds=10, periodSeconds=10)}  # fmt: skip

    def pod(owner, started, ready):
        return {"metadata": {"namespace": "pay", "name": f"{owner}-7c9d6f5b8-{started[-2:]}{ready[-2:]}x",
                             "ownerReferences": [{"kind": "ReplicaSet", "name": f"{owner}-7c9d6f5b8"}]},
                "spec": {"nodeName": "n1"},
                "status": {"phase": "Running",
                           "conditions": [{"type": "Ready", "status": "True", "lastTransitionTime": ready}],
                           "containerStatuses": [{"state": {"running": {"startedAt": started}}}]}}  # fmt: skip

    lists = _lists() | {
        "/apis/apps/v1/deployments": [
            deploy("shared", readinessProbe=http("/health"), livenessProbe=http("/health", timeoutSeconds=5)),
            deploy("tight", readinessProbe=http("/ready"), livenessProbe=http("/live")),  # Kubernetes's 1s default
            deploy("tcp", readinessProbe=http("/ready"), livenessProbe={"tcpSocket": {"port": 8080}}),
            deploy("slow", **slow),
            deploy("guarded", **slow, startupProbe=http("/live", failureThreshold=30)),
            deploy("bare"),
        ],
        "/apis/autoscaling/v2/horizontalpodautoscalers": [],
        "/api/v1/pods": [
            # liveness allows about 10 + 10 x 3 = 40s; the quicker of the two pods took 25s
            pod("slow", "2026-11-12T10:00:00Z", "2026-11-12T10:00:25Z"),
            pod("slow", "2026-11-12T10:00:00Z", "2026-11-12T10:01:00Z"),
            pod("guarded", "2026-11-12T10:00:00Z", "2026-11-12T10:00:25Z"),
            pod("tight", "2026-11-12T10:00:00Z", "2026-11-12T10:00:05Z"),
        ],
    }  # fmt: skip
    got = collector.read_workloads(lambda path, cap: lists[path])
    found = {(r["rule"], r["res"].split("/")[-1]): r for r in workload_rows({"name": "c", "region": "r", **got},
                                                                            OutageAnswers())}  # fmt: skip
    by_rule = lambda rule: {w for r, w in found if r == rule}  # noqa: E731
    assert by_rule("eks_liveness_same") == {"shared"}
    assert by_rule("eks_liveness_tight") == {"tight"}  # a TCP connect is not slowed by load
    assert by_rule("eks_slow_start") == {"slow"}  # the startup probe holds liveness off
    assert "25s" in found[("eks_slow_start", "slow")]["note"] and "40s" in found[("eks_slow_start", "slow")]["note"]
    assert by_rule("eks_no_liveness") == {"bare"} and "bare" in by_rule("eks_no_readiness")


def test_platform_namespaces_match_wildcards_and_leave_cluster_checks_running():
    workloads = [
        {"ns": "kube-system", "name": "coredns", "kind": "Deployment", "replicas": 2},
        {"ns": "Tools-System", "name": "x", "kind": "Deployment", "replicas": 2},
        {"ns": "systemics", "name": "app", "kind": "Deployment", "replicas": 2},
    ]
    a = OutageAnswers(platform_namespaces="kube-*, *-system")
    got = workload_rows({"name": "c", "region": "r", "workloads": workloads}, a)
    assert "eks_coredns" in {r["rule"] for r in got}  # a cluster check, though kube-system is the platform's
    assert not [r for r in got if "/x" in r["res"]]  # wildcard, any case
    assert [r for r in got if "/app" in r["res"]]  # *-system does not match a namespace merely containing it


def test_coredns_needs_three_on_three_nodes_in_production_two_elsewhere_and_no_autoscaler():
    from exitrisk.outage import _judge, catalog

    rule = next(r for r in catalog()["rules"] if r["id"] == "eks_coredns")

    def judged(production, **w):
        w = {"ns": "kube-system", "name": "coredns", "kind": "Deployment", **w}
        rows = [r for r in workload_rows({"name": "c", "region": "r", "workloads": [w]}, OutageAnswers())
                if r["rule"] == "eks_coredns"]  # fmt: skip
        return [f for r in rows if (f := _judge(r, rule, OutageAnswers(), date(2026, 11, 27), 15, production))]

    assert judged(True, replicas=2, on_nodes=2) and judged(False, replicas=2, on_nodes=2) == []
    assert judged(False, replicas=1, on_nodes=1)  # under 2 fails everywhere
    assert judged(False, replicas=3, on_nodes=1)  # three replicas sharing one node: the spread fails
    assert "3 replicas on 2 node(s)" in judged(True, replicas=3, on_nodes=2)[0]["note"]
    assert judged(True, replicas=3, on_nodes=3) == []  # a fixed count, no autoscaler: fine
    assert judged(True, replicas=4, pods_placed=3) == []  # an older scan: the nodes read stand in
    assert judged(True, replicas=3) == []  # placement unknown: not guessed


def test_eks_token_is_a_presigned_call_that_names_the_cluster():
    sts = boto3.Session(aws_access_key_id="AKIAFAKE", aws_secret_access_key="fake", region_name="eu-west-1").client(
        "sts"
    )
    token = collector.eks_token(sts, "my-cluster", "eu-west-1")
    assert token.startswith("k8s-aws-v1.")
    raw = token.removeprefix("k8s-aws-v1.")
    url = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
    query = parse_qs(urlparse(url).query)
    assert urlparse(url).netloc == "sts.eu-west-1.amazonaws.com"
    assert query["Action"] == ["GetCallerIdentity"]
    assert "x-k8s-aws-id" in query["X-Amz-SignedHeaders"][0]
    assert query["X-Amz-Expires"] == ["60"]


class _CW:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def get_metric_data(self, **kw):
        self.calls.append(kw)
        return self.pages.pop(0) if self.pages else {"MetricDataResults": []}


class _Session:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **_):
        return self.clients[name]


def _ctx(clients, services=None):
    return collector.OutageCtx(
        _Session(clients), "111111111111", ["eu-west-1"], {"services": services, "home": "eu-west-1"}
    )


def test_metrics_are_read_once_and_the_label_names_the_resource():
    when = datetime(2026, 10, 1, tzinfo=timezone.utc)
    cw = _CW([{"MetricDataResults": [
        {"Label": "q0~i-123", "Timestamps": [when, when + timedelta(hours=1)], "Values": [40.0, 80.0]}
    ]}])  # fmt: skip
    ctx = _ctx({"cloudwatch": cw})
    got = ctx.metrics("eu-west-1")
    first = next(iter(collector.METRICS))
    assert got[first]["i-123"].high == 80.0
    calls = len(cw.calls)
    ctx.metrics("eu-west-1")
    assert len(cw.calls) == calls
    assert all("SEARCH(" in q["Expression"] for c in cw.calls for q in c["MetricDataQueries"])
    assert all(len(c["MetricDataQueries"]) <= 500 for c in cw.calls)


class _Paged:
    """A client whose list calls return one fixed page; other calls refuse."""

    def __init__(self, **pages):
        self.pages = pages

    def can_paginate(self, _):
        return False

    def __getattr__(self, name):
        if name in self.pages:
            return lambda **_: self.pages[name]

        def refuse(**_):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, name)

        return refuse


def test_msk_disk_filling_imbalance_and_no_autoscaling_are_found():
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    disk = collector.METRICS["msk_disk"]
    assert disk[2] == "KafkaDataLogsDiskUsed"
    ctx = _ctx({})
    full, empty = collector.Series(), collector.Series()
    full.add(now, 85.0)
    empty.add(now, 40.0)
    ctx._metrics["eu-west-1"] = {k: {} for k in collector.METRICS} | {
        "msk_disk": {"kafka-1|1": full, "kafka-1|2": empty}
    }
    ctx.clients = None
    ctx.session = _Session({
        "kafka": _Paged(list_clusters_v2={"ClusterInfoList": [{
            "ClusterName": "kafka-1", "ClusterArn": "arn:x",
            "Provisioned": {"NumberOfBrokerNodes": 2, "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large", "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1000}}}},
        }]}),
        "application-autoscaling": _Paged(describe_scalable_targets={"ScalableTargets": []}),
    })  # fmt: skip
    collector.task_msk(ctx, "eu-west-1")
    rules = {r["rule"]: r for r in ctx.rows}
    assert rules["msk_disk"]["pct"] == 85.0
    assert "msk_imbalance" in rules and "msk_no_autoscale" in rules


def _series(*values):
    s, now = collector.Series(), datetime(2026, 10, 1, tzinfo=timezone.utc)
    for i, v in enumerate(values):
        s.add(now + timedelta(hours=i), v)
    return s


def test_target_groups_that_lost_every_target_or_run_one_are_found():
    from exitrisk.collectors import outage_services as svc

    ctx = _ctx({})
    lb = "app/shop/abc"
    ctx._metrics["eu-west-1"] = {k: {} for k in collector.METRICS} | {
        "alb_healthy": {f"targetgroup/web/1|{lb}": _series(0, 3), f"targetgroup/api/2|{lb}": _series(1, 1),
                        f"targetgroup/idle/3|{lb}": _series(0, 0), "targetgroup/x/4|app/other/z": _series(0, 2)},
        "alb_healthy_max": {f"targetgroup/web/1|{lb}": _series(3, 3), f"targetgroup/api/2|{lb}": _series(1, 1),
                            f"targetgroup/idle/3|{lb}": _series(0, 0), "targetgroup/x/4|app/other/z": _series(2, 2)},
    }  # fmt: skip
    ctx.session = _Session({"elbv2": _Paged(describe_load_balancers={"LoadBalancers": [{
        "LoadBalancerName": "shop", "Type": "application", "LoadBalancerArn": f"arn:aws:x:1:loadbalancer/{lb}",
        "AvailabilityZones": [{"ZoneName": "a"}, {"ZoneName": "b"}]}]})})  # fmt: skip
    svc.task_lb_review(ctx, "eu-west-1")
    got = {(r["rule"], r["res"]) for r in ctx.rows}
    assert got == {("lb_no_healthy", "shop: web"), ("lb_single_target", "shop: api")}


def test_each_vpn_tunnel_is_judged_against_its_own_limit():
    from exitrisk.collectors import outage_services as svc

    ctx = _ctx({})
    gbit_hour = 1e9 / 8 * collector.PERIOD  # bytes in an hour at 1 Gbps
    m = {k: {} for k in collector.METRICS} | {
        "vpn_in": {"vpn-1|1.1.1.1": _series(gbit_hour), "vpn-1|2.2.2.2": _series(1)}
    }
    svc._vpn_bandwidth(ctx, m, "vpn-1", svc.VPN_TUNNEL_BPS["standard"], "eu-west-1")
    assert [(r["res"], r["pct"], r["limit"]) for r in ctx.rows] == [("vpn-1 tunnel 1.1.1.1", 80.0, 1250)]


def test_a_volume_is_judged_against_its_provisioned_iops_and_throughput():
    ctx = _ctx({})
    hour = collector.PERIOD
    ctx._metrics["eu-west-1"] = {k: {} for k in collector.METRICS} | {
        "ebs_rops": {"vol-1": _series(1500 * hour)},
        "ebs_wops": {"vol-1": _series(1200 * hour)},
        "ebs_wbytes": {"vol-1": _series(100 * 1024**2 * hour)},
    }
    vols = [
        {"VolumeId": "vol-1", "VolumeType": "gp3", "Iops": 3000, "Throughput": 125, "Size": 500},
        {"VolumeId": "vol-2", "VolumeType": "gp2", "Iops": 1500, "Size": 500},  # judged by burst balance
    ]
    collector._volume_headroom(ctx, vols, "eu-west-1")
    got = {r["res"]: (r["pct"], r["used"], r["limit"]) for r in ctx.rows}
    assert got == {"vol-1": (90.0, 2700, 3000), "vol-1 throughput": (80.0, 100, 125)}
    assert all(r["load"] for r in ctx.rows)


def test_lambda_concurrency_is_judged_against_reservations_and_the_shared_pool():
    from exitrisk.collectors import outage_services as svc

    class Lambda:
        def get_function_concurrency(self, FunctionName):
            return {"ReservedConcurrentExecutions": {"pay": 100, "off": 0}.get(FunctionName)}

        def get_account_settings(self):
            return {"AccountLimit": {"UnreservedConcurrentExecutions": 900}}

    ctx = _ctx({})
    m = {k: {} for k in collector.METRICS} | {
        "lambda_fconc": {"pay": _series(90), "off": _series(5), "free": _series(40)},
        "lambda_unres": {"all": _series(450)},
    }
    fns = [{"FunctionName": n} for n in ("pay", "off", "free", "idle")]
    svc._lambda_concurrency(ctx, Lambda(), m, fns, "eu-west-1")
    got = {r["rule"]: (r["res"], r["pct"]) for r in ctx.rows}
    assert got == {"lambda_reserved": ("pay", 90.0), "lambda_unreserved": ("Lambda unreserved concurrency", 50.0)}


def test_lambda_events_need_enough_failures_to_count():
    from exitrisk.collectors import outage_services as svc

    ctx = _ctx({})
    m = {k: {} for k in collector.METRICS} | {
        "lambda_err": {"a": _series(60, 60), "b": _series(5)},
        "lambda_iter": {"a": _series(10, 400_000)},
        "lambda_async_drop": {"b": _series(0, 3)},
    }
    svc._lambda_events(ctx, m, "a", _series(1000, 1000), "eu-west-1")
    svc._lambda_events(ctx, m, "b", _series(10), "eu-west-1")  # 50% of 10: too few to judge
    assert {(r["rule"], r["res"]) for r in ctx.rows} == {
        ("lambda_errors", "a"),
        ("lambda_iterator_age", "a"),
        ("lambda_async_dropped", "b"),
    }


def test_a_refused_read_is_recorded_as_not_measured_and_is_not_a_pass():
    ctx = _ctx({"kafka": _Paged()})
    collector._run(ctx, ("msk", ("msk",), collector.task_msk, None), "eu-west-1")
    assert not ctx.rows
    assert ctx.r.finish()["msk"]["status"] != "ok"


def test_a_task_that_runs_twice_counts_its_rows_once(monkeypatch):
    def twice(ctx, region):
        ctx.add("msk_disk", "a", region, pct=90.0)
        ctx.add("msk_disk", "a", region, pct=90.0)

    monkeypatch.setattr(collector, "GLOBAL_TASKS", [])
    monkeypatch.setattr(collector, "REGION_TASKS", [("twice", ("msk",), twice, None)])
    monkeypatch.setattr(collector, "_finish", lambda ctx: None)
    monkeypatch.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
    out, _ = collector.account_checks(object(), "111111111111", ["eu-west-1"], {})
    assert len(out["rows"]) == 1


# -------------------------------------------------------------------- the report


def test_report_on_the_demo_is_available_and_adds_up(report):
    s = report["summary"]
    assert report["available"] and s["accounts"] > 0
    assert s["critical"] == sum(x["critical"] for x in report["focus"])
    assert s["high"] == sum(x["high"] for x in report["focus"])
    assert sum(a["critical"] for a in report["accounts"]) >= s["critical"]
    assert report["findings"][0]["severity"] == "critical"
    assert s["clusters_read"] < s["clusters"]  # the demo has clusters with no access entry


def test_every_rule_in_the_demo_is_in_the_catalog(scan):
    ids = {r["id"] for r in catalog()["rules"]}
    for acct in scan["outage"]["accounts"].values():
        assert {r["rule"] for r in acct.get("rows") or []} <= ids


def test_every_cause_has_a_source_and_says_what_it_cannot_show():
    for c in catalog()["causes"]:
        assert c["url"].startswith("https://") and c["source"] and c["limits"] and c["evidence"]


def test_answers_change_the_result_with_no_new_scan(scan, report):
    calm = build_outage(scan, a=OutageAnswers(peak_multiplier=1.0))
    assert calm["summary"]["breach_at_peak"] < report["summary"]["breach_at_peak"]
    wider = build_outage(scan, a=OutageAnswers(cpu_request_floor_m=4000))
    assert wider["summary"]["all_findings"] > report["summary"]["all_findings"]


def test_a_peak_date_moves_the_dates_and_the_freeze(scan):
    r = build_outage(scan, a=OutageAnswers(peak_date="2027-01-31", freeze_days=7))
    assert r["summary"]["peak_date"] == "2027-01-31" and r["summary"]["freeze_date"] == "2027-01-24"


def test_outside_production_a_finding_is_one_level_lower():
    scan = {"accounts": [{"id": "1", "name": "dev", "ou_path": "Root"}], "params": {"outage": True}}
    row = {"rule": "msk_disk", "res": "k", "region": "eu-west-1", "pct": 95.0}
    scan["outage"] = {"accounts": {"1": {"rows": [row], "clusters": [], "checks": {}, "regions": ["eu-west-1"]}}}
    assert build_outage(scan)["findings"][0]["severity"] == "high"
    prod = build_outage(scan, a=OutageAnswers(production_patterns="dev"))
    assert prod["findings"][0]["severity"] == "critical"


@pytest.mark.parametrize(
    "kind, want",
    [
        ("t3.medium", ("t3", 20)),
        ("db.t4g.large", ("t4g", 30)),
        ("cache.t3.micro", ("t3", 10)),
        ("t3.small.search", ("t3", 20)),
        ("kafka.t3.small", ("t3", 20)),
        ("t2.2xlarge", ("t2", 16.9)),
        ("m5.large", None),
        ("db.r6g.large", None),
        ("", None),
    ],
)
def test_burstable_sizes_and_their_baselines(kind, want):
    assert collector.burstable(kind) == want


@pytest.mark.parametrize(
    "row, want",
    [
        ({"cpu": 15, "baseline": 20, "unlimited": False}, "high"),  # 30% at 2x load, over 20%
        ({"cpu": 15, "baseline": 20, "unlimited": True}, "medium"),  # bills instead of slowing
        ({"cpu": 5, "baseline": 20, "unlimited": False}, "low"),  # 10% at peak, under its baseline
        ({"baseline": 20, "unlimited": None}, "medium"),  # nothing says how busy
        ({"cpu": 5, "baseline": 20, "credits": 1.0, "unlimited": False}, "high"),  # already ran out
        ({"cpu": 5, "baseline": 20, "credits": 1.0, "unlimited": True}, "low"),  # unlimited: zero is normal
    ],
)
def test_a_burstable_size_is_judged_against_its_baseline_at_peak_load(row, want):
    sev, why = judge_burstable({"type": "t3.medium", **row}, OutageAnswers(peak_multiplier=2.0))
    assert sev == want and why.startswith("t3.medium")


def test_burstable_findings_are_production_only_and_name_the_service():
    rows = [
        {"rule": "ec2_burstable", "res": "web", "region": "eu-west-1", "type": "t3.large", "baseline": 30, "cpu": 40,
         "unlimited": False},
        {"rule": "rds_burstable", "res": "db", "region": "eu-west-1", "type": "db.t3.medium", "baseline": 20,
         "unlimited": True},
    ]  # fmt: skip
    for name, want in (("prod", 2), ("dev", 0)):
        scan = {"accounts": [{"id": "1", "name": name, "ou_path": "Root"}], "params": {"outage": True}}
        scan["outage"] = {"accounts": {"1": {"rows": rows, "clusters": [], "checks": {}, "regions": ["eu-west-1"]}}}
        found = build_outage(scan)["findings"]
        assert len(found) == want
        if want:
            assert {f["rule"]: f["severity"] for f in found} == {"ec2_burstable": "high", "rds_burstable": "medium"}


def test_a_filter_narrows_the_accounts(scan, report):
    r = build_outage(scan, AccountFilter(include="prod"))
    assert 0 < r["summary"]["accounts"] < report["summary"]["accounts"]


def test_a_scan_without_the_checks_says_so(scan):
    r = build_outage({**scan, "outage": None, "params": {**scan["params"], "outage": False}})
    assert r["available"] is False and "did not run" in r["reason"]


def test_csv_has_a_row_for_each_finding_and_cannot_run_a_formula(report):
    text = findings_csv(report)
    assert len(text.strip().splitlines()) == len(report["findings"]) + 1
    head = text.splitlines()[0].split(",")
    assert "owner" in head and head[-2:] == ["what to do", "accepted risk"]  # a team can filter to its own and act
    bad = {**report, "findings": [{**report["findings"][0], "res": "=cmd()"}]}
    assert ",'=cmd()," in findings_csv(bad)


# -------------------------------------------------------------------- against botocore's own API models


def _answering(status: int):
    """A real boto3 session with no network: botocore validates every call, and this answers it."""
    from botocore.awsrequest import AWSResponse

    denied = b"<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>"
    xml = ("iam.", "ec2.", "rds.", "autoscaling.", "elasticloadbalancing.", "route53.", "s3.", "sts.", "monitoring.")
    xml += ("cloudfront.", "elasticache.", "redshift.")

    class Raw:
        def __init__(self, body):
            self.body = body

        def stream(self, **_):
            body, self.body = self.body, None
            if body:
                yield body

    session = boto3.Session(aws_access_key_id="AKIAFAKE", aws_secret_access_key="fake", region_name="eu-west-1")

    def reply(request, **_):
        is_xml = urlparse(request.url).netloc.startswith(xml) or ".s3." in request.url
        if status == 403:
            return AWSResponse(request.url, 403, {}, Raw(denied if is_xml else b'{"__type": "AccessDeniedException"}'))
        if not is_xml:
            return AWSResponse(request.url, 200, {}, Raw(b"{}"))
        body = parse_qs(request.body.decode() if isinstance(request.body, bytes) else str(request.body or ""))
        action = (body.get("Action") or ["R"])[0]
        return AWSResponse(
            request.url, 200, {}, Raw(f"<{action}Response><{action}Result/></{action}Response>".encode())
        )

    session.events.register("before-send", reply)
    return session


@pytest.mark.parametrize("status", [403, 200])
def test_every_call_is_valid_for_its_api(monkeypatch, caplog, status):
    """A wrong operation or parameter name would only show on a real scan: this finds it with no AWS."""
    monkeypatch.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
    out, _ = collector.account_checks(_answering(status), "111111111111", ["eu-west-1"], {"home": "eu-west-1"})
    assert out["checks"]
    unexpected = [
        r.getMessage() + str(r.exc_info and r.exc_info[1]) for r in caplog.records if "unexpected" in r.getMessage()
    ]
    assert not unexpected
    if status == 403:
        assert not out["rows"]


def _one(rows, profiles=(), name="prod"):
    scan = {"accounts": [{"id": "1", "name": name, "ou_path": "Root"}], "params": {"outage": True}}
    scan["outage"] = {"accounts": {"1": {"rows": rows, "clusters": [], "checks": {}, "regions": ["r"],
                                         "profiles": list(profiles)}}}  # fmt: skip
    return build_outage(scan)["findings"]


def test_readings_that_cannot_be_true_are_not_findings():
    rows = [
        {"rule": "limit_product", "res": "sns: Messages Published per Second", "region": "r", "pct": 20003.0,
         "used": 60010.0, "limit": 300.0, "load": True},  # an enforced quota cannot be passed 200 times over
        {"rule": "sqs_backlog", "res": "orders-dlq", "region": "r", "pct": 100.0},
        {"rule": "sqs_backlog", "res": "replies", "region": "r", "pct": 100.0,
         "note": "oldest message 2 minutes old; deleted after 0 hours"},
        {"rule": "efs_burst", "res": "fs-1", "region": "r", "pct": 100.0},
        {"rule": "rds_memory", "res": "ora", "region": "r", "pct": 99.0},
    ]  # fmt: skip
    profiles = [
        {
            "svc": "efs",
            "res": "fs-1",
            "region": "r",
            "facts": {"Throughput": "bursting", "Size": "0.0 GiB"},
            "stats": [],
        },
        {"svc": "rds", "res": "ora", "region": "r", "facts": {"Engine": "oracle-ee 19"}, "stats": []},
    ]
    assert _one(rows, profiles) == []


def test_a_resource_named_for_a_test_stage_is_not_production():
    rows = [{"rule": "rds_single_az", "res": "billing-qa-db", "region": "r"}]  # production only
    assert _one(rows) == []


def test_evidence_beside_a_finding_lowers_it():
    rows = [
        {"rule": "lambda_timeout", "res": "f", "region": "r", "pct": 133.0, "load": True},
        {"rule": "kinesis_iterator", "res": "s", "region": "r", "pct": 100.0},
        {"rule": "limit_connect", "res": "connect: Rate of DescribeUser API requests", "region": "r", "pct": 99.0,
         "load": True},
    ]  # fmt: skip
    profiles = [
        {
            "svc": "lambda",
            "res": "f",
            "region": "r",
            "facts": {},
            "stats": [{"k": "Longest run", "peak": 40, "avg": 3}],
        },
        {
            "svc": "kinesis",
            "res": "s",
            "region": "r",
            "facts": {},
            "stats": [{"k": "Reader behind", "peak": 259200.0, "avg": 1276.0}],
        },
    ]
    assert {f["rule"]: f["severity"] for f in _one(rows, profiles)} == {
        "lambda_timeout": "medium",
        "kinesis_iterator": "medium",
        "limit_connect": "medium",
    }


def test_a_daily_quota_is_read_over_a_day_and_a_per_second_one_finely():
    daily = {"Period": {"PeriodValue": 1, "PeriodUnit": "DAY"}, "UsageMetric": {"MetricName": "CallCount"}}
    second = {"Period": {"PeriodValue": 1, "PeriodUnit": "SECOND"}, "UsageMetric": {"MetricName": "CallCount"}}
    assert collector._rate_period(daily) == 86400 and collector._rate_period(second) == collector.RATE_PERIOD


def test_every_critical_risk_is_listed_beyond_fifty():
    rows = [{"rule": "msk_offline", "res": f"k{i}", "region": "r", "used": 1, "unit": "x"} for i in range(3)]
    scan = {"accounts": [{"id": str(i), "name": f"prod{i}", "ou_path": "Root"} for i in range(60)],
            "params": {"outage": True}}  # fmt: skip
    scan["outage"] = {"accounts": {str(i): {"rows": rows, "clusters": [], "checks": {}, "regions": ["r"]}
                                   for i in range(60)}}  # fmt: skip
    top = build_outage(scan)["top_risks"]
    assert len(top) == 60 and all(f["severity"] == "critical" for f in top)


def _one_account(rows, profiles=()):
    scan = {"accounts": [{"id": "1", "name": "prod", "ou_path": "Root"}], "params": {"outage": True}}
    scan["outage"] = {"accounts": {"1": {"rows": rows, "clusters": [], "checks": {}, "regions": ["eu-west-1"],
                                         "profiles": list(profiles)}}}  # fmt: skip
    return scan


@pytest.mark.parametrize(
    "row, fires",
    [
        ({"maintenance": "mon:05:00-mon:05:30", "backup": "", "multi_az": True}, True),  # 07:00 local
        ({"maintenance": "sun:23:00-sun:23:30", "backup": "", "multi_az": True}, False),  # 01:00 local
        ({"maintenance": "sun:23:00-sun:23:30", "backup": "06:00-06:30", "multi_az": True}, False),  # from standby
        ({"maintenance": "sun:23:00-sun:23:30", "backup": "06:00-06:30", "multi_az": False}, True),
        ({"maintenance": "garbage", "backup": "", "multi_az": False}, False),
    ],
)
def test_database_windows_are_judged_in_local_busy_hours(row, fires):
    rows = [{"rule": "rds_busy_window", "res": "db", "region": "af-south-1", **row}]
    found = build_outage(_one_account(rows))["findings"]
    assert bool(found) == fires
    if fires:
        assert "UTC+2" in found[0]["why"] and found[0]["severity"] == "medium"


def test_busy_hours_are_an_answer_needing_no_new_scan():
    rows = [{"rule": "rds_busy_window", "res": "db", "region": "eu-west-1", "maintenance": "mon:05:00-mon:05:30"}]
    assert build_outage(_one_account(rows))["findings"]
    late = OutageAnswers(busy_hours="08:00-18:00")
    assert not build_outage(_one_account(rows), a=late)["findings"]  # 07:00 local is before 08:00
    assert build_outage(_one_account(rows), a=OutageAnswers(busy_hours="08:00-18:00", utc_offset=4))["findings"]


def test_aurora_and_mysql_memory_is_measured_against_what_the_cache_leaves():
    """Aurora PostgreSQL on 16 GiB showing 1.8 GiB freeable is normal: its cache holds the rest by design."""
    row = {"rule": "rds_memory", "res": "a", "region": "eu-west-1", "pct": 89.0, "note": "db.r7g.large"}
    aurora = {"svc": "rds", "res": "a", "region": "eu-west-1", "facts": {"Engine": "aurora-postgresql 16.11"},
              "stats": []}  # fmt: skip
    assert not build_outage(_one_account([row], [aurora]))["findings"]
    tight = {**row, "pct": 98.0}  # 2% free: 92% of the quarter left over is used
    assert build_outage(_one_account([tight], [aurora]))["findings"][0]["severity"] == "critical"
    plain = {**aurora, "facts": {"Engine": "postgres 16.3"}}
    assert build_outage(_one_account([row], [plain]))["findings"]


def test_no_free_storage_alarm_is_asked_of_aurora():
    rows = [
        {"rule": "no_alarm", "res": "rds: a", "region": "eu-west-1", "note": "no CloudWatch alarm on FreeStorageSpace"}
    ]
    aurora = {"svc": "rds", "res": "a", "region": "eu-west-1", "facts": {"Engine": "aurora-postgresql 16"}, "stats": []}
    assert not build_outage(_one_account(rows, [aurora]))["findings"]
    plain = {**aurora, "facts": {"Engine": "postgres 16"}}
    assert build_outage(_one_account(rows, [plain]))["findings"]


@pytest.mark.parametrize(
    "kind, family",
    [
        ("m4.large", "m4"), ("db.r4.xlarge", "r4"), ("cache.t2.micro", "t2"), ("r4.large.search", "r4"),
        ("mq.t2.micro", "t2"), ("i3.2xlarge", "i3"), ("m5.large", None), ("db.r7g.large", None),
        ("t3.medium", None), ("db.serverless", None), ("", None), ("kafka.m5.large", None),
    ],
)  # fmt: skip
def test_old_generation_is_xen_hardware_whatever_the_service(kind, family):
    got = collector.old_generation(kind)
    assert (got[0] if got else None) == family


def test_a_scheduled_aws_event_counts_only_when_it_lands_by_the_peak():
    soon = (date.today() + timedelta(days=3)).isoformat()
    later = (black_friday() + timedelta(days=60)).isoformat()
    rows = [{"rule": "ec2_event", "res": "web", "region": "eu-west-1", "ends": d, "note": "system-reboot"}
            for d in (soon, later)]  # fmt: skip
    found = build_outage(_one_account(rows))["findings"]
    assert [f["why"].split(":")[0] for f in found] == [f"applies on {soon}"]


def test_a_service_review_says_what_is_wrong_with_each_resource():
    rows = [{"rule": "rds_single_az", "res": "a", "region": "eu-west-1", "note": "db.r6g.large, postgres"}]
    prof = {"svc": "rds", "res": "a", "region": "eu-west-1", "facts": {"Engine": "postgres 16"}, "stats": []}
    r = build_outage(_one_account(rows, [prof]))
    rds = next(s for s in r["services"] if s["id"] == "rds")
    issues = rds["resource_rows"][0]["issues"]
    assert issues and issues[0]["title"] == "Production database in one availability zone"


def test_aurora_serverless_is_judged_by_cpu_against_the_maximum_not_by_capacity_used():
    # Capacity used is held up by the buffer cache; AWS measures Serverless v2 CPU against the maximum ACUs.
    rows = [
        {"rule": "aurora_acu", "res": "idle", "region": "r", "pct": 59.0, "load": True},
        {"rule": "aurora_acu", "res": "busy", "region": "r", "pct": 95.0, "load": True},
        {"rule": "aurora_acu", "res": "blind", "region": "r", "pct": 99.0, "load": True},
    ]

    def cpu(res, peak):
        return {"svc": "rds", "res": res, "region": "r", "facts": {}, "stats": [{"k": "CPU", "peak": peak, "avg": 3}]}

    found = {f["res"]: f for f in _one(rows, [cpu("idle", 7.8), cpu("busy", 94.0)])}
    assert "idle" not in found
    assert found["busy"]["severity"] == "critical" and "capacity used 95%" in found["busy"]["why"]
    assert found["blind"]["severity"] == "medium" and "insufficient evidence" in found["blind"]["why"]


def test_only_evidence_of_an_outage_stays_critical_or_high():
    def prof(svc, res, **stats):
        rows = [{"k": k.replace("_", " "), "peak": v[0], "avg": v[1]} for k, v in stats.items()]
        return {"svc": svc, "res": res, "region": "r", "facts": {}, "stats": rows}

    rows = [
        {"rule": "apigw_5xx", "res": "quiet", "region": "r", "used": 5},
        {"rule": "apigw_5xx", "res": "failing", "region": "r", "used": 29161},
        {"rule": "msk_under_replicated", "res": "patched", "region": "r", "used": 3},
        {"rule": "msk_under_replicated", "res": "stuck", "region": "r", "used": 3, "now": 2},
        {"rule": "nat_drops", "res": "nat-1", "region": "r", "used": 19},
        {"rule": "lambda_throttles", "res": "nightly", "region": "r", "used": 500},
        {"rule": "aurora_no_reader", "res": "sonarqube-prod-inst-1", "region": "r"},
        {"rule": "limit_connect", "res": "connect-prod: phone numbers", "region": "r", "pct": 100.0},
    ]
    profiles = [
        prof("apigateway", "quiet", Requests=(0.05, 0.01), Server_errors=(3, 0.03)),
        prof("apigateway", "failing", Requests=(2.99, 0.11), Server_errors=(9049, 182.26)),
        prof("lambda", "nightly", Invocations=(0.01, 0.0), Throttles=(30, 0.6)),
    ]
    found = {f["res"]: f for f in _one(rows, profiles)}
    assert found["quiet"]["severity"] == "low" and "noise" in found["quiet"]["why"]
    assert found["failing"]["severity"] == "high" and "of requests" in found["failing"]["why"]
    assert "patched" not in found and found["stuck"]["severity"] == "high"  # recovered: not an issue
    assert found["nat-1"]["severity"] == "low"
    assert found["nightly"]["severity"] == "medium" and "background job" in found["nightly"]["why"]
    assert not found.get("sonarqube-prod-inst-1", {}).get("production")
    assert found["connect-prod: phone numbers"]["severity"] == "medium"


def test_immediate_attention_lists_what_will_most_likely_cause_an_outage_in_production_only():
    from exitrisk.outage_views import _immediate

    today = date(2026, 11, 4)
    rules = {
        "msk_offline": {"kind": "event", "fix": "Find the broker."},
        "ec2_cpu": {"kind": "capacity", "fix": "Resize."},
        "rds_maintenance": {"kind": "config", "fix": "Apply it in a quiet window."},
        "search_storage": {"kind": "capacity", "fix": "Grow it."},
    }
    base = {"res": "r1", "region": "af-south-1", "account_id": "1", "account": "prd-a", "title": "t", "pct": None}
    base |= {"days": None, "production": True, "service_label": "S"}
    findings = [
        {**base, "rule": "rds_maintenance", "severity": "high", "why": "applies on 2026-11-07: upgrade"},
        {**base, "rule": "rds_maintenance", "severity": "high", "why": "applies on 2026-12-30: upgrade", "res": "r9"},
        {**base, "rule": "search_storage", "severity": "critical", "why": "fills", "pct": 70, "days": 18},
        {**base, "rule": "msk_offline", "severity": "critical", "why": "1 offline"},
        {**base, "rule": "ec2_cpu", "severity": "critical", "why": "at 100%", "pct": 100},
        {**base, "rule": "ec2_cpu", "severity": "critical", "why": "at 96%", "pct": 96, "res": "r2"},
        {**base, "rule": "ec2_cpu", "severity": "high", "why": "80% now", "pct": 80, "account_id": "2"},
        {
            **base,
            "rule": "ec2_cpu",
            "severity": "critical",
            "why": "x",
            "pct": 100,
            "production": False,
            "account_id": "3",
        },
    ]
    table = [{"id": "1", "owner": "Team A"}, {"id": "2", "owner": ""}, {"id": "3", "owner": ""}]
    got = _immediate(findings, table, rules, today)
    whens = [r["when"] for r in got["rows"]]
    assert whens == ["Failed in the last 35 days", "At or past its limit now", "Full in about 18 days"]  # no upgrades
    assert (
        got["rows"][1]["more"] == 1 and got["rows"][1]["owner"] == "Team A" and got["rows"][1]["do_by"] == "2026-11-04"
    )
    assert got["total"] == 3 and got["accounts"] == 1 and got["resources"] == 4


def test_a_queue_at_its_expiry_is_judged_by_whether_anyone_reads_it_and_if_it_has_caught_up():
    rows = [
        {"rule": "sqs_backlog", "res": "unread", "region": "r", "pct": 100.0, "sent": 8826247, "received": 0},
        {"rule": "sqs_backlog", "res": "idle", "region": "r", "pct": 100.0, "sent": 0, "received": 0},
        {"rule": "sqs_backlog", "res": "caught-up", "region": "r", "pct": 94.0, "sent": 9, "received": 9,
         "age_now_pct": 0.0},
        {"rule": "sqs_backlog", "res": "stalled", "region": "r", "pct": 100.0, "sent": 9000, "received": 10,
         "age_now_pct": 100.0},
    ]  # fmt: skip
    prof = [{"svc": "sqs", "res": n, "region": "r", "facts": {}, "stats": [{"k": "Messages waiting", "peak": 5000}]}
            for n in ("unread", "idle", "caught-up", "stalled")]  # fmt: skip
    got = {f["res"]: f for f in _one(rows, prof)}
    assert got["unread"]["severity"] == "medium" and "nobody reads this queue" in got["unread"]["why"]
    assert got["idle"]["severity"] == "low"
    assert got["caught-up"]["severity"] == "medium" and "caught up" in got["caught-up"]["why"]
    assert got["stalled"]["severity"] == "critical"
    sink = [{"rule": "sqs_backlog", "res": "prd-sms-process-invalid-prd", "region": "r", "pct": 100.0, "received": 9}]
    assert _one(sink)[0]["severity"] == "medium"


def test_connect_api_rates_follow_the_staff_not_the_peak_and_admin_calls_are_not_customer_traffic():
    rows = [
        {"rule": "limit_connect", "res": "connect: Rate of UpdateUserHierarchy API requests", "region": "r",
         "pct": 106.0, "used": 2.1, "limit": 2.0, "load": True},
        {"rule": "limit_connect", "res": "connect: Rate of StartOutboundVoiceContact API requests", "region": "r",
         "pct": 105.3, "used": 5.26, "limit": 5.0, "load": True},
        {"rule": "limit_connect", "res": "connect: Rate of StartChatContact API requests", "region": "r",
         "pct": 60.0, "used": 3.0, "limit": 5.0, "load": True},
    ]  # fmt: skip
    got = {f["res"].split()[3]: f for f in _one(rows)}
    assert got["UpdateUserHierarchy"]["severity"] == "medium" and "admin API" in got["UpdateUserHierarchy"]["why"]
    out = got["StartOutboundVoiceContact"]
    assert out["severity"] == "high" and out["at_peak"] == out["pct"] and "staff is fixed" in out["why"]
    assert got["StartChatContact"]["severity"] in ("medium", "low")


def test_dns_domain_and_certificate_findings_are_judged_by_date_and_auto_renewal():
    soon = (date.today() + timedelta(days=10)).isoformat()
    far = (date.today() + timedelta(days=100)).isoformat()
    rows = [
        {"rule": "domain_expiry", "res": "lapsing.example", "region": "global", "ends": soon, "auto": False},
        {"rule": "domain_expiry", "res": "renewing.example", "region": "global", "ends": far, "auto": True},
        {"rule": "cert_renewal_failing", "res": "api.example", "region": "r", "ends": soon, "now": True,
         "note": "renewal pending validation"},
        {"rule": "r53_failover_no_check", "res": "api.example A", "region": "global", "note": "zone example"},
    ]  # fmt: skip
    got = {f["res"]: f for f in _one(rows)}
    assert got["lapsing.example"]["severity"] == "critical"
    assert "renewing.example" not in got  # renews by itself, well after the peak
    assert got["api.example"]["severity"] == "critical"
    assert got["api.example A"]["severity"] == "high"


def test_serverless_peaks_are_judged_against_todays_maximum_acus():
    from datetime import datetime, timedelta, timezone

    from exitrisk.collectors.outage import serverless_usage

    t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
    hours = {k: {} for k in ("ua", "ca", "cm", "pa", "pm")}
    for h in range(48):
        when = t0 + timedelta(hours=h)
        top = 32 if h < 24 else 256  # the maximum was raised from 32 to 256 halfway
        cap = 32 if h < 24 else 40
        hours["ca"][when] = hours["cm"][when] = cap
        hours["ua"][when] = cap / top * 100
        hours["pa"][when] = hours["pm"][when] = 100 if h < 24 else 10
    use = serverless_usage(hours, 256)
    assert use["changed"] == {"until": "2026-10-01", "was": 32}
    assert use["cpu_acus"] == 32 and use["cpu_pct"] == 12.5  # 100% of 32 ACUs is 12.5% of 256
    assert use["acu_pct"] == 15.6 and use["ceiling_hours"] == 0


def test_serverless_advice_says_the_range_and_what_to_raise_the_maximum_to():
    from exitrisk.outage import OutageAnswers, acu_advice

    a = OutageAnswers()
    row = {"rule": "aurora_acu", "acu_min": 4, "acu_max": 128, "cpu_acus": 68.7, "changed": None}
    said = acu_advice(row, a)
    assert "now 4 to 128 ACUs" in said and "raise the maximum to 200 ACUs" in said
    big = acu_advice({**row, "cpu_acus": 120}, a)
    assert "past the 256 Aurora Serverless v2 allows" in big
    fine = acu_advice({**row, "cpu_acus": 20, "changed": {"until": "2026-10-21", "was": 64}}, a)
    assert "the maximum was 64 until 2026-10-21" in fine and "today's maximum covers that" in fine


def test_a_fault_that_has_recovered_is_not_reported():
    rows = [
        {"rule": "msk_offline", "res": "fixed-on-sunday", "region": "r", "used": 93, "now": 0},
        {"rule": "msk_offline", "res": "still-down", "region": "r", "used": 4, "now": 2},
        {"rule": "msk_offline", "res": "older-scan", "region": "r", "used": 1},  # read before "now" was kept
        {"rule": "msk_offline", "res": "older-fixed", "region": "r", "used": 93},
        {"rule": "msk_under_replicated", "res": "older-fixed", "region": "r", "used": 2, "now": 0},
    ]
    found = {f["res"]: f for f in _one(rows)}
    assert "fixed-on-sunday" not in found
    assert found["still-down"]["severity"] == "critical" and "older-scan" in found
    assert "older-fixed" not in found  # its cluster is fully replicated now, so the partitions are back


def test_a_rate_quota_without_a_period_is_read_as_a_rate_from_its_name_and_says_which_limit():
    """SNS "Messages Published per Second" has no period from AWS: read as a level, the busiest hour's calls
    were set against 300 a second and 167 accounts showed it full."""
    q = {
        "QuotaCode": "L-F8E2BA85",
        "QuotaName": "Messages Published per Second",
        "Value": 300.0,
        "UsageMetric": {"MetricName": "CallCount", "MetricNamespace": "AWS/Usage"},
    }
    assert collector._is_rate(q) and collector._quota_seconds(q) == 1
    assert collector._rate_period(q) == collector.RATE_PERIOD
    # SNS publishes this rate as a ResourceCount (NumberOfMessagesPublishedPerAccount): still a rate.
    assert collector._is_rate({**q, "UsageMetric": {"MetricName": "ResourceCount"}})
    assert not collector._is_rate(
        {**q, "QuotaName": "DB subnet groups", "UsageMetric": {"MetricName": "ResourceCount"}}
    )
    assert not collector._is_rate({**q, "QuotaName": "Topics"})
    ctx = collector.OutageCtx(None, "111111111111", ["af-south-1"], {})
    stat = {
        "Metric": {
            "Namespace": "AWS/Usage",
            "MetricName": "CallCount",
            "Dimensions": [{"Name": "Service", "Value": "SNS"}, {"Name": "Resource", "Value": "Publish"}],
        },
        "Period": 300,
        "Stat": "Sum",
    }
    collector._quota_row(ctx, "af-south-1", "sns", q, 300.0 * 120, datetime(2026, 11, 8, 14, 5), stat)
    row = ctx.rows[0]
    assert row["used"] == 120 and row["pct"] == 40 and row["unit"] == "a second"
    from exitrisk.outage import limit_basis

    text = limit_basis(row)
    assert "Limit 300 a second (Service Quotas L-F8E2BA85)" in text
    assert "Highest 120 a second on 2026-11-08 at 14:05 UTC" in text
    assert "AWS/Usage CallCount (Service SNS, Resource Publish): Sum per 5 minutes" in text


def test_a_saved_scan_leaves_out_rate_quotas_read_as_levels():
    from exitrisk.outage import _settled_rate_quotas

    old = {"rule": "limit_product", "res": "sns: Messages Published per Second", "qcode": "L-F8E2BA85", "used": 318.0}
    rate = {**old, "res": "logs: DescribeLogGroups throttle limit in transactions per second", "used": 4.59}
    new = {**old, "used": 120.0, "metric": "AWS/Usage CallCount", "unit": "a second"}
    level = {**old, "res": "lambda: Concurrent executions", "used": 1000.0}
    assert _settled_rate_quotas([old, rate, new, level]) == [rate, new, level]


def test_a_saved_sns_rate_read_as_the_busiest_hours_sum_becomes_that_hours_average():
    from exitrisk.outage import _settled_rate_quotas

    row = {"rule": "limit_product", "res": "sns: Messages Published per Second", "qcode": "L-F8E2BA85",
           "used": 316.0, "limit": 300.0, "pct": 105.3, "metric": "AWS/Usage ResourceCount",
           "read": "Sum per 1 hour, the busiest in 14 days"}  # fmt: skip
    assert _settled_rate_quotas([row]) == []  # 316 an hour is 0.09 a second: far under the limit
    busy = {**row, "used": 300.0 * 3600 * 0.5}
    (got,) = _settled_rate_quotas([busy])
    assert got["used"] == 150 and got["pct"] == 50 and got["unit"] == "a second"


def test_nodes_show_not_ready_pressure_and_requests_against_what_they_hold():
    def pod(node, cpu, mem, phase="Running"):
        return {
            "metadata": {"namespace": "a", "name": f"p-{node}-{cpu}"},
            "status": {"phase": phase},
            "spec": {"nodeName": node, "containers": [{"resources": {"requests": {"cpu": cpu, "memory": mem}}}]},
        }

    def node(name, ready="True", **pressure):
        conds = [{"type": "Ready", "status": ready}] + [{"type": k, "status": "True"} for k in pressure]
        return {
            "metadata": {"name": name},
            "status": {"conditions": conds, "allocatable": {"cpu": "2", "memory": "4Gi"}},
        }

    pods = [pod("n1", "500m", "1Gi"), pod("n2", "1", "2Gi"), pod("n2", "1", "1Gi", "Succeeded")]
    lists = {**_lists(), "/api/v1/pods": pods,
             "/api/v1/nodes": [node("n1"), node("n2", DiskPressure=1), node("n3", ready="False")]}  # fmt: skip
    read = lambda path, cap: lists[path]  # noqa: E731
    c = {"access": "read", **collector.read_workloads(read), **collector.read_nodes(read), "node_access": "read"}
    assert (c["req_cpu"], c["req_mem"]) == (1500, 3072)  # the finished pod reserves nothing
    view = _node_view(c)
    assert view["nodes"] == 3 and view["not_ready"] == ["n3"] and view["pressure"] == {"DiskPressure": ["n2"]}
    assert view["requested_pct"] == {"cpu": 25, "mem": 25}
    # Pods read only up to the limit: the sum would be short, so no percentage.
    assert _node_view({**c, "pods_cut": True})["requested_pct"] is None
    assert _node_view({"access": "read", "node_access": "refused"}) == {"node_access": "refused"}
    assert _node_view({"access": "read"}) == {"node_access": "not read"}
