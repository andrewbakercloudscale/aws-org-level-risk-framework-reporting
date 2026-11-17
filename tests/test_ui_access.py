"""The Access Graph in a real browser: the graph draws, hops and direction change it, picking an account
re-centres it.

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


def _open(page, console):  # noqa: F811
    page.goto(console.replace("view=multiregion", "view=access"))
    page.wait_for_selector("body[data-ready='1']")
    page.wait_for_selector("#agContent:not([hidden])")


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


def test_picking_an_account_recentres_the_graph(page, console):  # noqa: F811
    _open(page, console)
    page.locator("#agAccounts [data-ag-pick]").nth(1).click()
    title = page.text_content("#agGraphTitle")
    assert "payments-core-prod" not in title
    assert page.input_value("#agAccount") != page.locator("#agAccount option").first.get_attribute("value")
    assert not page.errors
