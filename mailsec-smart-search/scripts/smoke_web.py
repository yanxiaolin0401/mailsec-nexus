"""Optional Playwright smoke for an unconfigured-model local demo deployment.

Run smoke_events.py first. Requires Playwright/Chromium as external QA tools,
not application dependencies. Uses only synthetic rows from that smoke report.
Do not run against a server configured for paid model calls.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright, expect

report = json.loads(Path("docs/reports/json-events-smoke.json").read_text())
source = report["source_system_id"]
if os.getenv("MAILSEC_LLM_API_KEY"):
    raise SystemExit("This smoke requires an unconfigured model (no external calls).")
errors = []
with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
    )
    page = browser.new_page(viewport={"width": 1440, "height": 1100})
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto("http://127.0.0.1:8080/")
    page.locator("#token").fill(os.environ["MAILSEC_API_TOKEN"])
    page.locator("#search-form summary").click()
    page.locator("input[name=source_system_id]").fill(source)
    page.locator("#search-form button[type=submit]").click()
    expect(page.locator("#count")).to_contain_text("共 3 条")
    assert page.locator("#rows tr").count() == 3
    page.locator("#rows button").first.click()
    expect(page.locator("#detail")).to_be_visible()
    assert "raw_json" not in page.locator("#detail-content").inner_text()
    page.locator("#analyze-event").click()
    expect(page.locator("#analysis-result")).to_contain_text(
        "analysis_id", timeout=20000
    )
    analysis = json.loads(page.locator("#analysis-result").inner_text())
    assert analysis["status"] == "partial" and analysis["risk_level"] == "unknown"
    page.locator("#close-detail").click()
    page.locator("#question").fill("查询最近带 PDF 附件的邮件")
    page.locator("#nl-form button[type=submit]").click()
    expect(page.locator("#status")).to_have_class("error")
    assert "503" in page.locator("#status").inner_text()
    # Keep synthetic rows on screen for the evidence screenshot, then clear all state.
    page.screenshot(path="docs/reports/web-console-smoke.png", full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert (
        page.evaluate("localStorage.length") == 0
        and page.evaluate("sessionStorage.length") == 0
    )
    page.locator("#forget").click()
    assert (
        page.locator("#token").input_value() == ""
        and page.locator("#rows tr").count() == 0
    )
    browser.close()
    assert errors == [], errors
    result = {
        "at": datetime.now(timezone.utc).isoformat(),
        "browser": "Playwright Chromium headless",
        "source_system_id": source,
        "checks": {
            "search_rows": 3,
            "detail": True,
            "analysis_persisted_partial_unknown": True,
            "unconfigured_nl_visible_503": True,
            "mobile_no_page_overflow": True,
            "token_not_persisted_and_clear": True,
            "javascript_errors": errors,
        },
        "external_model_calls": 0,
    }
    Path("docs/reports/web-console-smoke.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    )
    print(json.dumps(result, ensure_ascii=False))
