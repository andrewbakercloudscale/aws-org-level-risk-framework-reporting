"""Cloud Assurance in a real browser: the owner bubble chart draws and a bubble opens that owner's actions.

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
    pg.goto(console.replace("view=multiregion", "view=assurance").replace("&include=prod", ""))
    pg.wait_for_selector("body[data-ready='1']")
    yield pg
    ctx.close()


def test_risk_by_owner_draws_above_the_actions(page):
    page.wait_for_function("document.querySelector('#chAsOwners').width > 300")
    first = page.evaluate("document.querySelector('#as-owners .card').id")
    assert first == "asOwnerMap"
    assert "No owner tag" in page.locator("#asOwnersNote").inner_text()
    assert not page.locator("#asOwnerMap .chart-empty, #asOwnerMap .chart-error").count()
    owners = page.evaluate("[...document.querySelectorAll('#asOwners .owner-block')].map((b) => b.dataset.owner)")
    assert owners and all(owners)
    assert not page.errors


def test_what_should_i_do_next_lists_each_leader(page):
    blocks = page.locator("#asNext .next-block")
    assert blocks.count() >= 2
    first = blocks.first
    rows = first.locator(".next-table > tbody > tr:not(.next-sev)")
    assert 1 <= rows.count() <= 10
    assert first.locator("tr.next-sev").count() >= 1  # grouped by severity
    assert rows.first.locator("td").first.inner_text().strip() == "1"
    assert "risk points" in rows.first.inner_text()
    assert "remove" in page.locator("#asNextLead").inner_text()
    assert page.locator("#asTopFind .find-table").count() >= 1
    assert not page.errors
