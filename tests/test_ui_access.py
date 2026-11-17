"""The Access Graph in a real browser. Organisation reach: the graph draws, hops and direction change it,
picking an account re-centres it. Account map: the account's ways in and out draw with their icons,
selecting one shows its details, selecting another account opens its map, and Back returns.

Skipped where Chromium is not installed (`playwright install chromium`); CI's ui job runs it.
"""

import pytest
from test_ui_multiregion import browser, console  # noqa: F401 - shared fixtures

sync_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture
def page(browser, console):  # noqa: F811
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.errors = errors
    yield pg
    ctx.close()


def _open(page, console, mode="reach", everything=False):  # noqa: F811
    url = console.replace("view=multiregion", "view=access")
    page.goto(url.replace("&include=prod", "") if everything else url)
    page.wait_for_selector("body[data-ready='1']")
    page.wait_for_selector("#agContent:not([hidden])")
    if mode == "reach":
        page.click("#agModeReach")
        page.wait_for_selector("#agReachPart:not([hidden])")
    else:
        page.wait_for_selector("#agMapSvg .agm-node")


def _nodes(page):
    return page.locator("#agSvg .ag-node").count()


def test_graph_draws_and_hops_widen_it(page, console):  # noqa: F811
    _open(page, console)
    assert page.locator('#subTabs button[data-part="access"][aria-pressed="true"]').count() == 1
    assert "payments-core-prod" in page.text_content("#agGraphTitle")
    page.select_option("#agHops", "1")
    one = _nodes(page)
    assert one > 5  # every account on the production gateway can reach the 10.0.0.0/8 database rule
    page.select_option("#agHops", "3")
    assert _nodes(page) >= one
    rows = page.locator("#agTable tbody tr")
    assert rows.count() > 3
    assert "Security group range" in page.text_content("#agTable")
    assert not page.errors


def test_iam_only_and_direction(page, console):  # noqa: F811
    _open(page, console)
    page.uncheck("#agNet")
    page.select_option("#agHops", "1")
    text = page.text_content("#agTable")
    assert "Role trust" in text and "Security group" not in text
    page.select_option("#agDir", "out")
    assert page.text_content("#agGraphTitle").startswith("What payments-core-prod can reach")
    assert not page.errors


def test_what_can_reach_me_lists_sources_worst_first(page, console):  # noqa: F811
    _open(page, console)
    assert page.text_content("#agReachMeTitle") == "What can reach payments-core-prod?"
    groups = page.locator("#agReachMe tr.ag-reach-group th").all_text_contents()
    assert groups[0].startswith("The internet and anyone") and groups[-1].startswith("Accounts in the organisation")
    assert "Security group range" in page.text_content("#agReachMe")
    # it answers "reach me" whatever direction the graph shows
    page.select_option("#agDir", "out")
    assert page.locator("#agReachMe tr.ag-reach-group").count() == len(groups)
    page.uncheck("#agNet")
    assert "Security group range" not in page.text_content("#agReachMe")
    assert not page.errors


def test_picking_an_account_recentres_the_graph(page, console):  # noqa: F811
    _open(page, console)
    page.locator("#agAccounts [data-ag-pick]").nth(1).click()
    title = page.text_content("#agGraphTitle")
    assert "payments-core-prod" not in title
    assert page.input_value("#agAccount") != page.locator("#agAccount option").first.get_attribute("value")
    assert not page.errors


def _map_nodes(page):
    return [n.get_attribute("data-agm-node") for n in page.locator("#agMapSvg .agm-node").all()]


def test_account_map_draws_ways_in_and_out_with_flows(page, console):  # noqa: F811
    _open(page, console, mode="map")
    assert page.get_attribute("#agModeMap", "aria-selected") == "true"
    assert page.locator("#agReachPart").is_hidden()
    page.select_option("#agMapAccount", label=page.locator("#agMapAccount option", has_text="digital-channels-prod")
                       .first.text_content())  # fmt: skip
    sync_api.expect(page.locator("#agMapTitle")).to_contain_text("digital-channels-prod")
    ids = _map_nodes(page)
    assert "internet" in ids and "aws" in ids
    assert any(i.startswith("igw-") for i in ids) and any(i.startswith("nat-") for i in ids)
    assert any(i.startswith("tgw:") for i in ids) and any(i.startswith("lb:") for i in ids)
    assert page.locator("#agMapSvg .agm-node path").count() == len(ids)  # every box carries its icon
    assert "Crossed the edge" in page.text_content("#agFlows")
    assert "GB" in page.text_content("#agWays")
    page.check("#agMapUsed")
    assert len(_map_nodes(page)) < len(ids)  # paths that carried nothing are hidden
    page.uncheck("#agMapUsed")
    page.select_option("#agMapDir", "out")
    assert not any(i.startswith("lb:") for i in _map_nodes(page))  # a public load balancer is a way in only
    assert not page.errors


def test_failed_traffic_lists_every_kind_and_who_was_refused(page, console):  # noqa: F811
    _open(page, console, mode="map")
    page.select_option("#agMapAccount", label=page.locator("#agMapAccount option", has_text="digital-channels-prod")
                       .first.text_content())  # fmt: skip
    sync_api.expect(page.locator("#agMapTitle")).to_contain_text("digital-channels-prod")
    box = page.locator("#agFail")
    sync_api.expect(box.locator(".ag-fail-tile")).to_have_count(5)
    assert box.locator(".ag-fail-table tbody tr").count() >= 27  # every kind, 0 included
    text = box.text_content()
    assert "Requests blocked by web ACL rules" in text and "none in this account" in text
    assert "11 ports:" in text  # the scan stands out
    assert "also refused at the network" in text
    assert box.locator("tr.ag-fail-hit").count() > 3
    # a public address links to whois and abuse reports; a private one does not
    link = box.locator("a[href='https://ipinfo.io/185.220.101.34']").first
    assert link.get_attribute("rel") == "noopener noreferrer"
    assert box.locator("a[href*='abuseipdb.com/check/185.220.101.34']").count() >= 1
    assert box.locator("a[href*='ipinfo.io/10.']").count() == 0
    # a table over 20 rows shows 20 until asked for the rest
    kinds = box.locator(".ag-fail-table")
    more = box.locator(".cap-more button").first
    assert kinds.locator("tbody tr:visible").count() == 20 and "Show all" in more.text_content()
    more.click()
    assert kinds.locator("tbody tr:visible").count() >= 27
    assert not page.errors


def test_account_map_details_and_pivot(page, console):  # noqa: F811
    _open(page, console, mode="map")
    first = page.text_content("#agMapTitle")
    nat_or_tgw = page.locator("#agMapSvg .agm-node[data-agm-node^='tgw:']").first
    nat_or_tgw.click()
    assert page.locator("#agMapDetail").is_visible()
    assert "Transit gateway" in page.text_content("#agMapDetail")
    page.locator("#agWays [data-agm-open]").first.click()
    sync_api.expect(page.locator("#agMapTitle")).not_to_have_text(first)
    assert page.locator("#agMapBack").is_visible()
    page.click("#agMapBack")
    sync_api.expect(page.locator("#agMapTitle")).to_have_text(first)
    assert not page.errors


def test_routing_read_shows_real_transit_gateway_reach(page, console):  # noqa: F811
    _open(page, console, mode="map", everything=True)  # the non-production gateway's routing is read
    opt = page.locator("#agMapAccount option", has_text="data-platform-dev").first
    page.select_option("#agMapAccount", opt.get_attribute("value"))
    sync_api.expect(page.locator("#agMapTitle")).to_contain_text("data-platform-dev")
    page.locator("#agMapSvg .agm-node[data-agm-node^='tgw:']").first.click()
    detail = page.text_content("#agMapDetail")
    assert "blackhole" in detail and "uses route table non-production" in detail
    assert not page.locator("#agMapSvg [data-agm-node^='members:']").count()  # not assumed: routing was read
    assert not page.errors
