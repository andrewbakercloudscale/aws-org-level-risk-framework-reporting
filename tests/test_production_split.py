from exitrisk.assurance import is_production

P = ["prod", "prd"]


def acct(name, ou, tags=None):
    return {"name": name, "ou_path": ou, "tags": tags or {}}


def test_non_prod_ou_is_not_production():
    assert not is_production(acct("acme-x-pay", "Root / Non-Prod"), P)
    assert not is_production(acct("acme-x-pay", "Root / NonProd"), P)
    assert not is_production(acct("acme-x-pay", "Root / Pre-Prod"), P)


def test_name_decides_before_ou():
    assert not is_production(acct("acme-npr-pay", "Root / Prod"), P)
    assert not is_production(acct("acme-ppd-pay", "Root / Workloads"), P)
    assert is_production(acct("acme-prd-pay", "Root / Workloads"), P)
    assert is_production(acct("acme-pay", "Root / Production"), P)
    assert not is_production(acct("acme-pay", "Root / Workloads"), P)


def test_words_that_only_contain_a_mark_do_not_count():
    assert is_production(acct("acme-devops-prd", "Root"), P)
    assert is_production(acct("acme-testament", "Root / Prod"), P)


def test_tag_wins():
    assert is_production(acct("acme-npr-pay", "Root / Non-Prod", {"Environment": "production"}), P)
    assert not is_production(acct("acme-prd-pay", "Root / Prod", {"env": "dev"}), P)
