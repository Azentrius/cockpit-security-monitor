#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Screenshots of the preview in the light and the dark theme, on a desktop
and a phone, e.g. for the README or to check a UI change. The page follows
the browser's colour scheme like Cockpit's "auto" style (azentrius-theme.js).
Needs Playwright with Chromium:

    pip install playwright && python3 -m playwright install chromium
    python3 tools/preview/build.py
    python3 tools/preview/shoot.py [output-dir]      (default: docs/img)

Fails if the page throws a JavaScript error or scrolls horizontally on a
phone-sized screen (every scenario and tab, both themes, both languages,
also with the dialog open).
"""
import os
import sys

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PAGE = os.path.join(HERE, "out", "security", "index.html")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "docs", "img")
SCENARIOS = ("ufw-docker", "hetzner-open", "nft-native")
TABS = ("exposure", "ssh", "logins", "containers", "crowdsec")


def main():
    if not os.path.exists(PAGE):
        sys.exit("Build first: python3 tools/preview/build.py")
    os.makedirs(OUT, exist_ok=True)
    errors, widths = [], {}
    with sync_playwright() as p:
        browser = p.chromium.launch()

        def page(width, height, query, scheme="light"):
            pg = browser.new_page(viewport={"width": width, "height": height}, color_scheme=scheme)
            pg.on("pageerror", lambda e: errors.append(f"{query}: {e}"))
            pg.goto(f"file://{PAGE}?{query}")
            pg.wait_for_timeout(700)
            return pg

        def width(pg):
            return pg.evaluate("() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]")

        pg = page(1440, 1000, "scenario=ufw-docker&lang=en")
        pg.screenshot(path=os.path.join(OUT, "exposure.png"))
        pg.locator("#sm-port-tcp-8080 details").evaluate("d => d.open = true")
        pg.locator("#sm-ports").screenshot(path=os.path.join(OUT, "ports.png"))
        pg = page(1440, 1000, "scenario=ufw-docker&lang=en", "dark")
        pg.screenshot(path=os.path.join(OUT, "exposure-dark.png"))
        pg = page(1440, 1000, "scenario=hetzner-open&lang=en&tab=ssh")
        pg.screenshot(path=os.path.join(OUT, "ssh.png"))
        pg = page(1440, 1000, "scenario=nft-native&lang=en&tab=containers")
        pg.screenshot(path=os.path.join(OUT, "containers.png"))
        pg = page(1440, 900, "scenario=ufw-docker&lang=en")
        pg.click("#sm-port-tcp-8080 [data-expect-port]")
        pg.fill("#sm-dialog-input", "Test page for the office")
        pg.wait_for_timeout(200)
        pg.screenshot(path=os.path.join(OUT, "mark-dialog.png"))
        pg = page(1440, 900, "scenario=ufw-docker&lang=en&admin=0")
        pg.screenshot(path=os.path.join(OUT, "no-admin.png"))

        for scheme in ("light", "dark"):
            for sc in SCENARIOS:
                for lang in ("en", "de"):
                    for tab in TABS:
                        pg = page(390, 1400, f"scenario={sc}&lang={lang}&tab={tab}", scheme)
                        pg.evaluate("() => document.querySelectorAll('details').forEach((d) => { d.open = true; })")
                        widths[f"{sc} {lang} {tab} {scheme}"] = width(pg)
                        if sc == "ufw-docker" and lang == "en" and tab == "exposure":
                            pg.screenshot(path=os.path.join(OUT, f"mobile{'-dark' if scheme == 'dark' else ''}.png"))
                        pg.close()
        pg = page(390, 844, "scenario=ufw-docker&lang=de")
        pg.click("#sm-port-tcp-8080 [data-expect-port]")
        pg.wait_for_timeout(300)
        widths["dialog on a phone"] = pg.evaluate("() => { const d = document.getElementById('sm-dialog');"
                                                  " return [d.scrollWidth, d.clientWidth]; }")
        browser.close()

    print("Screenshots:", OUT)
    if errors:
        sys.exit("JavaScript errors: " + "; ".join(errors))
    for what, (scroll, client) in widths.items():
        if scroll > client:
            sys.exit(f"Horizontal scrolling on the phone ({what}): {scroll} > {client}")


if __name__ == "__main__":
    main()
