from exitrisk.assurance import is_production, prod_rule, production_why

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


def test_lists_and_words_from_the_answers():
    from exitrisk.outage import OutageAnswers

    a = OutageAnswers(production_accounts="acme-npr-pay, 111", nonproduction_accounts="acme-prd-lab2")
    rule = prod_rule(a)
    assert production_why(acct("acme-npr-pay", "Root / Non-Prod"), rule) == (True, "listed")
    assert production_why({"id": "111", "name": "x", "ou_path": "Root"}, rule) == (True, "listed")
    assert production_why(acct("acme-prd-lab2", "Root / Prod", {"env": "prod"}), rule) == (False, "listed")
    # Shared core accounts count by default
    assert production_why(acct("acme-core-network", "Root / Core Engineering"), rule) == (True, "name")
    assert production_why(acct("Audit", "Root / Core"), rule) == (True, "ou")
    # Words the user removes no longer count
    loose = prod_rule(OutageAnswers(nonproduction_patterns="npr"))
    assert is_production(acct("acme-pay", "Root / Pre-Prod"), loose)
    assert not is_production(acct("acme-npr-pay", "Root / Prod"), loose)


def test_hyphen_words_match_their_spellings():
    rule = prod_rule(prod=["prod"])
    for ou in ("Root / Non-Prod", "Root / NonProd", "Root / non_prod", "Root / Non Production", "Root / PreProd"):
        assert production_why(acct("acme-pay", ou), rule)[0] is False, ou
