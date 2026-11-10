from exitrisk.collectors.outage import karpenter_clusters


class Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return self.pages


class FakeEc2:
    def __init__(self, instances, templates):
        self.instances, self.templates = instances, templates

    def get_paginator(self, op):
        if op == "describe_instances":
            return Pager([{"Reservations": [{"Instances": self.instances}]}])
        return Pager([{"LaunchTemplates": self.templates}])


def tags(**kv):
    return [{"Key": k, "Value": v} for k, v in kv.items()]


def test_clusters_found_from_node_and_template_tags():
    ec2 = FakeEc2(
        [
            {"Tags": tags(**{"karpenter.sh/nodepool": "default", "eks:eks-cluster-name": "alpha"})},
            {"Tags": tags(**{"karpenter.sh/nodepool": "default", "eks:eks-cluster-name": "alpha"})},
            {"Tags": tags(**{"karpenter.sh/provisioner-name": "p", "kubernetes.io/cluster/beta": "owned"})},
        ],
        [{"Tags": tags(**{"karpenter.k8s.aws/cluster": "gamma"})}],
    )
    assert karpenter_clusters(ec2) == {"alpha": 2, "beta": 1, "gamma": 0}


def test_no_karpenter():
    assert karpenter_clusters(FakeEc2([], [])) == {}
