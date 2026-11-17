"""A real browser's checks of the portal's live refresh (live_refresh_test.go):
a page refreshing itself changes only its live parts, and leaves the user's
place, sort, filter, open menus and fields as they were."""
import sys
from playwright.sync_api import sync_playwright

base = sys.argv[1]
failures = []


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def copied(pg, table):
    return pg.eval_on_selector_all(f"#{table} tbody tr td:last-child", "tds => tds.map(t => t.textContent.trim())")


with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))

    # 1. The mirrors list refreshes its tables in place, without reloading.
    pg.goto(base + "/admin?section=mirrors")
    pg.evaluate("window.marker = 'still here'")
    first = copied(pg, "admin-mirrors")
    pg.wait_for_timeout(2600)
    check("the mirrors' table changed", copied(pg, "admin-mirrors") != first)
    check("no reload (the page's own state kept)", pg.evaluate("window.marker") == "still here")
    check("no meta refresh in the head", pg.evaluate("document.head.querySelector('meta[http-equiv=refresh]') === null"))

    # 2. Sort by owner, descending; it stays sorted across refreshes.
    owner = "#admin-mirrors thead th:nth-child(4)"
    pg.click(owner)
    pg.click(owner)
    order = pg.eval_on_selector_all("#admin-mirrors tbody tr td:first-child", "tds => tds.map(t => t.textContent.trim())")
    pg.wait_for_timeout(2600)
    after = pg.eval_on_selector_all("#admin-mirrors tbody tr td:first-child", "tds => tds.map(t => t.textContent.trim())")
    check(f"the sort kept across refreshes ({order} -> {after})", order == after and order[0] in ("beta",))
    check("the sort marker kept", pg.get_attribute(owner, "aria-sort") == "descending")

    # 3. On the server page: an open menu in a live part stays open, and the
    # review form's typed name and unticked row stay as left.
    pg.goto(base + "/admin/server?id=old")
    pg.evaluate("window.marker = 'server'")
    # (The form first: a click outside an open menu closes it, by design.)
    pg.fill("input[name=local-0]", "delta-renamed")
    pg.uncheck("input[name=pick][value='0']")
    pg.click("summary:has-text('Replace the key')")
    before = pg.inner_text("#server-mirrors")
    pg.wait_for_timeout(2600)
    check("an open menu in a live part stays open", pg.evaluate("[...document.querySelectorAll('.server-actions details')].some(d => d.open)"))
    check("the typed name kept", pg.input_value("input[name=local-0]") == "delta-renamed")
    check("the unticked row kept", not pg.is_checked("input[name=pick][value='0']"))
    check("the mirrored table still refreshed", pg.inner_text("#server-mirrors") != before)
    check("no reload on the server page", pg.evaluate("window.marker") == "server")

    # 4. From a refreshing page to another section, in place: no snap back.
    pg.goto(base + "/admin?section=mirrors")
    pg.evaluate("window.marker = 'nav'")
    pg.click("a.section:has-text('People')")
    pg.wait_for_url("**section=people")
    pg.wait_for_timeout(3000)
    check("stays on People (no snap back)", "section=people" in pg.url and pg.evaluate("document.body.dataset.refresh || ''") == "")
    check("moved in place, not reloaded", pg.evaluate("window.marker") == "nav")

    # 5. To a refreshing page, in place too (no full load), and it refreshes.
    pg.click("a.section:has-text('Mirrors')")
    pg.wait_for_url("**section=mirrors")
    check("went to Mirrors in place", pg.evaluate("window.marker") == "nav")
    first = copied(pg, "admin-mirrors")
    pg.wait_for_timeout(2600)
    check("and it refreshes there", copied(pg, "admin-mirrors") != first)

    check(f"no script errors {errors}", not errors)
    b.close()

sys.exit(1 if failures else 0)
