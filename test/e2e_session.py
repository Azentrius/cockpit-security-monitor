#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The add-on in a real Cockpit session, on a throw-away machine with systemd,
UFW and Docker (CI, test workflow, job e2e; never a machine you use).
Playwright drives Chromium through Cockpit's own login and shell. Spec 4.7:

  0. Cockpit before the add-on is installed: the errors the browser shows for
     Cockpit itself, as the baseline;
  1. this build installed with apt;
  2. as an administrator: right after the login Cockpit loads the page hidden
     for its menu icon, and it checks nothing until shown; the page in
     Cockpit's menu; with no state yet it checks by itself, through
     cockpit-security-scan.service; Docker's 0.0.0.0:8080 is "reachable from
     the internet, UFW does not apply here"; the state 0600, the status 0644,
     every source read; the menu icon as the status verb says; fail2ban's
     jail on 8080 with Ubuntu's default ban at the hook input is "does not
     protect container ports", its banned address listed (stage 2a); a
     socket-activated sshd without /run/sshd is "not checkable" with the fix
     the page names (decision 9.6), and that fix is then applied;
  3. the status for the Status Board, as a user without sudo, with 8080/tcp
     as a finding of its own (fid, link, first sighting) and a check per area;
  4. 8080/tcp marked as expected from the page, then the mark removed: only
     /etc/cockpit-security-monitor/exposure.conf changes;
  5. a DOCKER-USER rule, "Refresh": 8080/tcp is "VPN only", and sshd -T is read;
  6. the regular check set up from the page, then switched off;
  7. a user without administrative access (German browser): the menu icon in
     German before the page is opened, then the summary only;
  8. a link #/ssh opens the SSH tab with the configuration; cockpit.jump to
     another tab while the page is shown, to the row of 8080/tcp
     (#/exposure/8080-tcp, the link of its finding) while it is shown, and
     into another tab while it is hidden, without loading it again;
  9. no JavaScript error and no failed request of the add-on's files, and no
     error of another kind than the baseline's.

Environment: ADMIN_USER, ADMIN_PW (sudo group), PLAIN_USER, PLAIN_PW, NEW_DEB,
NEW_VERSION (test/e2e/setup.sh did the rest). Writes screenshots, report.json,
report.md and the raw outputs of the sources (capture/, for fixtures) to the
folder given; exit 1 if a step failed.
"""
import json
import os
import re
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

URL = "https://localhost:9090"
E = os.environ
OUT = sys.argv[1] if len(sys.argv) > 1 else "e2e-session"
FRAME = 'iframe[name$="/security"]'
STATE = "/var/lib/cockpit-security-monitor/state.json"
STATUS = "/var/lib/cockpit-security-monitor/status.json"
MARKS = "/etc/cockpit-security-monitor/exposure.conf"
OURS = "/security/"
os.makedirs(OUT, exist_ok=True)

report = {"environment": {}, "steps": [], "errors": []}
failed = False
errors = []          # [kind, text, url, user, phase]
PHASE = {"now": "baseline"}
shots = 0
LAST = {"page": None}
BASELINE = set()


def note(name, ok, detail=""):
    global failed
    failed |= not ok
    report["steps"].append({"step": name, "ok": bool(ok), "detail": detail})
    print(("OK   " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""), flush=True)
    return ok


def root(*cmd, check=True):
    p = subprocess.run(["sudo", "env", "DEBIAN_FRONTEND=noninteractive", *cmd], capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(cmd)} -> {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p.stdout.strip()


def shot(page, name):
    global shots
    shots += 1
    page.screenshot(path=os.path.join(OUT, f"{shots:02d}-{name}.png"), full_page=True)


def watch(page, who):
    page.on("console", lambda m: m.type == "error" and errors.append(
        ["console", m.text, (m.location or {}).get("url", ""), who, PHASE["now"]]))
    page.on("pageerror", lambda e: errors.append(["pageerror", f"{e.message}\n{e.stack or ''}", "", who, PHASE["now"]]))
    page.on("requestfailed", lambda r: errors.append(["requestfailed", r.failure or "", r.url, who, PHASE["now"]]))
    page.on("response", lambda r: r.status >= 400 and errors.append([f"http {r.status}", "", r.url, who, PHASE["now"]]))


def kind(e):
    return (e[0], e[1] if e[0] != "console" else e[1].split(" because ")[0], e[2] if e[0] != "console" else "")


def poll(page, fn, seconds):
    end = time.monotonic() + seconds
    while True:
        v = fn()
        if v or time.monotonic() > end:
            return v
        page.wait_for_timeout(250)


def login(browser, user, pw, locale="en-US"):
    ctx = browser.new_context(ignore_https_errors=True, locale=locale, viewport={"width": 1440, "height": 1000})
    page = ctx.new_page()
    page.set_default_timeout(90000)
    watch(page, user)
    page.goto(URL + "/", wait_until="domcontentloaded")
    page.fill("#login-user-input", user)
    page.fill("#login-password-input", pw)
    page.click("#login-button")
    LAST["page"] = page
    page.wait_for_selector("iframe, #login-error-message:not(:empty)", state="attached")
    if not page.locator("iframe").count():
        raise RuntimeError(f"login of {user} refused: " + page.locator("#login-error-message").inner_text())
    return ctx, page


def admin_access(page, pw):
    b = page.get_by_role("button", name=re.compile(r"^(Limited|Administrative) access$"))
    b.first.wait_for()
    if "Limited" in b.first.inner_text():
        b.first.click()
        dlg = page.get_by_role("dialog")
        dlg.locator("input[type=password]").fill(pw)
        dlg.get_by_role("button", name=re.compile("Authenticate")).click()
    page.get_by_role("button", name="Administrative access").wait_for()
    return True


def open_page(page):
    link = page.locator('a[href$="/security"]').first
    link.wait_for()
    label = link.inner_text().strip()
    link.click()
    frame = page.frame_locator(FRAME)
    frame.locator("#sm-sig-version").wait_for()
    poll(page, lambda: "Security Monitor " in (frame.locator("#sm-sig-version").text_content() or ""), 60)
    return frame, label


MENU_TYPES = {"danger": "error", "warning": "warning", "info": "info"}   # Cockpit's page status types


def shown_status(page):
    """The status the page sent the shell for its menu entry (the shell keeps every page's in the
    session storage); "unset" before the first."""
    stored = json.loads(page.evaluate("() => sessionStorage.getItem('cockpit:page_status')") or "{}")
    return stored.get("localhost", {}).get("security", "unset")


def check_menu(page, lang, what):
    """The icon and its tooltip as the status verb says, as a user without sudo (the file is
    fresh, so nothing is out of date): its state (ok and none: no icon) and its summary."""
    doc = status_doc(E["PLAIN_USER"], lang)
    want = {"type": MENU_TYPES[doc.get("state")], "title": doc.get("summary")} if doc.get("state") in MENU_TYPES else None
    icon = page.locator('a[href$="/security"] .nav-item-status')
    poll(page, lambda: shown_status(page) == want and icon.count() == (1 if want else 0), 60)
    got = shown_status(page)
    return note(f"{what}: the status icon in the menu as `status --lang {lang}` says",
                got == want and icon.count() == (1 if want else 0),
                f"state {doc.get('state')}, sent {json.dumps(got, ensure_ascii=False)}, icons {icon.count()}")


def own_frame(page):
    """The add-on's frame, to run code in it."""
    return next(f for f in page.frames if f.name.endswith("/security"))


def state():
    try:
        return json.loads(root("cat", STATE))
    except (RuntimeError, ValueError):
        return None


def status_doc(user, lang="en"):
    manifest = json.loads(root("cat", "/usr/share/cockpit/security/manifest.json"))
    verb = manifest.get("azentrius", {}).get("status") or ["false"]
    out = root("runuser", "-u", user, "--", *verb, "--lang", lang, check=False)
    try:
        return json.loads(out)
    except ValueError:
        return {}


def text(frame, sel):
    loc = frame.locator(sel)
    return " ".join((loc.first.inner_text() if loc.count() else "").split())


def port_row(frame):
    return frame.locator("#sm-port-tcp-8080")


def run_dialog(page, frame, opener, note_text=None, seconds=120):
    opener.click()
    confirm = frame.locator("#sm-dialog-confirm")
    poll(page, lambda: confirm.is_visible() and confirm.is_enabled(), 60)
    title = (frame.locator("#sm-dialog-title").text_content() or "").strip()
    if note_text is not None:
        frame.locator("#sm-dialog-input").fill(note_text)
    confirm.click()
    res = poll(page, lambda: (frame.locator("#sm-dialog-result").text_content() or "").strip(), seconds)
    ok = "is-ok" in (frame.locator("#sm-dialog-result").get_attribute("class") or "")
    log = frame.locator("#sm-dialog-log").text_content() or ""
    frame.locator("#sm-dialog-cancel").click()
    return title, res, ok, log


def capture():
    """The raw outputs of the sources on this machine, for fixtures (artifact only)."""
    d = os.path.join(OUT, "capture")
    os.makedirs(d, exist_ok=True)
    for name, cmd in (("ip-addr.json", ["ip", "-j", "addr"]), ("ss.txt", ["ss", "-H", "-tulpn"]),
                      ("iptables-save.txt", ["iptables-save"]), ("ip6tables-save.txt", ["ip6tables-save"]),
                      ("nft.json", ["nft", "-j", "list", "ruleset"]), ("sshd-T.txt", ["/usr/sbin/sshd", "-T"]),
                      ("docker-info.json", ["curl", "-s", "--unix-socket", "/var/run/docker.sock", "http://d/info"]),
                      ("docker-containers.json", ["curl", "-s", "--unix-socket", "/var/run/docker.sock",
                                                  "http://d/containers/json"]),
                      ("user.rules", ["cat", "/etc/ufw/user.rules"]),
                      ("f2b-version.txt", ["fail2ban-client", "--version"]),
                      ("f2b-status.txt", ["fail2ban-client", "status"]),
                      ("f2b-status-e2e-web.txt", ["fail2ban-client", "status", "e2e-web"]),
                      ("f2b-status-sshd.txt", ["fail2ban-client", "status", "sshd"]),
                      ("f2b-dump.txt", ["fail2ban-client", "-d"]),
                      ("systemctl-show-fail2ban.txt", ["systemctl", "show", "fail2ban.service", "-p", "ActiveState",
                                                       "-p", "UnitFileState", "-p", "ActiveEnterTimestamp"])):
        with open(os.path.join(d, name), "w") as f:
            f.write(root(*cmd, check=False))


def environment(browser):
    env = report["environment"]
    env["system"] = root("sh", "-c", ". /etc/os-release && echo \"$PRETTY_NAME\"") + ", kernel " + root("uname", "-r")
    env["cockpit"] = root("dpkg-query", "-W", "-f", "${Version}", "cockpit-ws")
    env["docker"] = root("docker", "version", "--format", "{{.Server.Version}}", check=False)
    env["iptables"] = root("iptables", "--version", check=False)
    env["ufw"] = root("ufw", "version", check=False).splitlines()[0] if root("ufw", "version", check=False) else ""
    env["python3"] = root("python3", "--version")
    env["browser"] = f"{browser.browser_type.name} {browser.version}"
    env["this build"] = E["NEW_VERSION"]


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        environment(browser)

        # 0. Cockpit on its own: the baseline of errors that are not the add-on's.
        ctx, page = login(browser, E["ADMIN_USER"], E["ADMIN_PW"])
        admin_access(page, E["ADMIN_PW"])
        page.goto(URL + "/system")
        page.wait_for_selector("iframe", state="attached")
        page.wait_for_timeout(3000)
        BASELINE.update(kind(e) for e in errors)
        note("Cockpit without the add-on: login, administrative access, the shell",
             not page.locator('a[href$="/security"]').count(), f"{len(BASELINE)} kinds of browser errors from Cockpit itself")
        ctx.close()

        # 1. This build.
        PHASE["now"] = "this build"
        root("apt-get", "install", "-y", "-q", E["NEW_DEB"])
        ver = root("dpkg-query", "-W", "-f", "${Version}", "cockpit-security-monitor")
        note("this build installed (apt)", ver.startswith(E["NEW_VERSION"]), ver)
        note("the timer comes with the package, off",
             root("systemctl", "is-enabled", "cockpit-security-scan.timer", check=False) == "disabled")

        # 2. As an administrator: the first check by itself; Docker's port past UFW.
        ctx, page = login(browser, E["ADMIN_USER"], E["ADMIN_PW"])
        note("administrator: administrative access", admin_access(page, E["ADMIN_PW"]))
        # Loaded hidden for the menu right after the login: it checks nothing by itself until shown.
        page.wait_for_selector(FRAME, state="attached")
        poll(page, lambda: shown_status(page) != "unset", 60)
        page.wait_for_timeout(3000)
        sig = (page.frame_locator(FRAME).locator("#sm-sig-version").text_content() or "").strip()
        note("after the login: the page loaded hidden for the menu, not started, no check yet",
             not page.locator(FRAME).is_visible() and sig == "Security Monitor" and state() is None
             and shown_status(page) is None,
             f"signature '{sig}', state {'none' if state() is None else 'written'}, sent {shown_status(page)!r}")
        frame, label = open_page(page)
        note("the page in the menu, this build's version",
             label == "Security Monitor" and E["NEW_VERSION"] in (frame.locator("#sm-sig-version").text_content() or ""),
             f"menu '{label}'")
        first = poll(page, lambda: state(), 300)
        port_row(frame).wait_for(timeout=180000)
        row = " ".join(port_row(frame).inner_text().split())
        cells = [" ".join(c.split()) for c in port_row(frame).locator("td").all_inner_texts()]
        note("Docker's 0.0.0.0:8080: reachable from the internet, UFW does not apply here (spec 4.7)",
             "Open to the internet" in row and "UFW does not apply here" in row and cells[2].split(" ")[0] in ("yes", "IPv4"),
             row[:300])
        p8080 = next((x for x in (first or {}).get("ports", []) if x["port"] == 8080 and x["proto"] == "tcp"), {})
        inet = ((p8080.get("reach") or {}).get("4") or {}).get("internet") or {}
        note("the state: forwarded past UFW to the container", inet.get("result") == "open" and inet.get("path") == "forward",
             json.dumps({k: inet.get(k) for k in ("result", "path", "to")})[:300])
        ssh = next((x for x in (first or {}).get("ports", []) if x["port"] == 22 and x["proto"] == "tcp"), {})
        note("sshd on 22 is not reachable from the internet but from the VPN (UFW)",
             ssh.get("reach", {}).get("4", {}).get("internet", {}).get("result") == "closed"
             and ssh.get("reach", {}).get("4", {}).get("vpn", {}).get("result") == "open", ssh.get("why", "no port 22"))
        modes = root("stat", "-c", "%a %U %n", STATE, STATUS)
        note("state.json 0600, status.json 0644, both root's", modes.splitlines() == [f"600 root {STATE}", f"644 root {STATUS}"],
             modes.replace("\n", "; "))
        unit = root("systemctl", "show", "cockpit-security-scan.service", "-p", "Result", "-p", "IPAddressDeny",
                    "-p", "CapabilityBoundingSet")
        note("the scan service ran, hardened, and succeeded", "Result=success" in unit and "IPAddressDeny=" in unit,
             unit.replace("\n", ", ")[:300])
        sources = (first or {}).get("sources", {})
        src = {k: v.get("state") for k, v in sources.items()}
        # Ubuntu's sshd is socket-activated: until the first connection /run/sshd is missing and
        # sshd -T fails (spec 4.3, decision 9.6). That is the one source allowed to fail here.
        privsep = (sources.get("sshd") or {}).get("reason") == "privsep-dir-missing"
        bad = {k: v for k, v in src.items() if v not in ("ok", "missing", "skipped") and not (k == "sshd" and privsep)}
        note("every source read in the real service", not bad, json.dumps(src))
        check_menu(page, "en", "after the first check")
        # fail2ban (stage 2a): Ubuntu's default ban at the hook input does not reach Docker's 8080.
        fb = (first or {}).get("fail2ban") or {}
        jail = next((j for j in fb.get("jails", []) if j["name"] == "e2e-web"), {})
        codes = [(f["code"], f.get("value")) for f in jail.get("findings", [])]
        note("fail2ban, read by the hardened scan service: the jail on 8080 bans at the hook input, which "
             "Docker's forwarding passes; the banned address listed (spec 5.3)",
             bool(fb.get("running")) and ("input-only", "8080/tcp") in codes
             and any(b["ip"] == "192.0.2.77" for b in fb.get("bans", [])),
             json.dumps({"running": fb.get("running"), "version": fb.get("version"), "e2e-web": codes,
                         "where": [a.get("where") for a in jail.get("actions", [])],
                         "bans": [b["ip"] for b in fb.get("bans", [])], "errors": fb.get("errors")})[:500])
        frame.locator("#sm-tab-btn-fail2ban").click()
        frame.locator("#sm-f2b-jail-e2e-web").wait_for(timeout=30000)
        jail_text = text(frame, "#sm-f2b-jail-e2e-web")
        note("the fail2ban tab: the jail with its warning, the ban in the list",
             "Docker forwards 8080/tcp past it" in jail_text and "192.0.2.77" in text(frame, "#sm-f2b-bans"),
             jail_text[:300])
        shot(page, "fail2ban")
        frame.locator("#sm-tab-btn-exposure").click()
        shot(page, "first-check")
        if privsep:
            frame.locator("#sm-tab-btn-ssh").click()
            ssh_text = text(frame, "#sm-sshd")
            note("sshd -T without /run/sshd (socket-activated sshd): not checkable, the page names the fix",
                 "sshd -T fails on this server" in ssh_text and "/etc/tmpfiles.d/sshd-privsep.conf" in ssh_text,
                 ssh_text[:200])
            shot(page, "sshd-privsep")
            # The fix as the page shows it, by hand (decision 9.6); the next check reads sshd -T.
            root("sh", "-c", "echo 'd /run/sshd 0755 root root -' > /etc/tmpfiles.d/sshd-privsep.conf"
                             " && systemd-tmpfiles --create")
            frame.locator("#sm-tab-btn-exposure").click()

        # 3. The status for the Status Board, as a user without sudo.
        st = status_doc(E["PLAIN_USER"], "de")
        items = {i.get("id"): i for i in st.get("items", [])}
        ex = items.get("exposure") or {}
        note("the status for the Status Board: read without root, in German, 8080/tcp a warning",
             st.get("schema") == 1 and st.get("version") == E["NEW_VERSION"] and ex.get("state") == "warning"
             and "8080/tcp" in ex.get("detail", "") and ex.get("title") == "Aus dem Internet erreichbar",
             f"{st.get('state')}: {ex}"[:300])
        found = (ex.get("findings") or {})
        f8080 = next((f for f in found.get("list") or [] if f.get("fid") == "port.8080-tcp"), {})
        checks = {c.get("id"): c for c in st.get("checks") or []}
        cx = checks.get("exposure") or {}
        note("the status names 8080/tcp as a finding of its own, and how each check went",
             st.get("features") == ["checks", "findings"] and f8080.get("state") in ("warning", "danger")
             and f8080.get("exposure") == "internet" and f8080.get("link") == "#/exposure/8080-tcp"
             and bool(f8080.get("since")) and list(checks) == ["exposure", "ssh", "logins", "containers", "crowdsec",
                                                              "fail2ban"]
             and cx.get("title") == "Aus dem Internet erreichbar" and found.get("complete") == (cx.get("state") == "checked")
             and (checks.get("fail2ban") or {}).get("state") in ("checked", "partial"),
             f"{f8080}; " + ", ".join(f"{k} {v.get('state')}" for k, v in checks.items()))

        # 4. Mark as expected, then remove the mark.
        before = root("sh", "-c", f"ls -la /etc/cockpit-security-monitor; cat {MARKS} 2>/dev/null || true")
        title, res, ok, log = run_dialog(page, frame, port_row(frame).locator("[data-expect-port='8080/tcp']"), "e2e test page")
        marks = root("cat", MARKS, check=False)
        mode = root("stat", "-c", "%a %U", MARKS, check=False)
        poll(page, lambda: "Marked as expected" in port_row(frame).inner_text(), 60)
        st = status_doc(E["PLAIN_USER"])
        note("8080/tcp marked as expected from the page: the line in exposure.conf, the status follows",
             ok and "port 8080/tcp e2e test page" in marks and mode == "644 root"
             and "Marked as expected" in port_row(frame).inner_text()
             and {i["id"]: i["state"] for i in st.get("items", [])}.get("exposure") == "info",
             f"{title} -> {res}; {mode}; {marks.splitlines()[-1] if marks else 'no file'}; before: {before[:120]}")
        shot(page, "marked")
        title, res, ok, log = run_dialog(page, frame, port_row(frame).locator("[data-unexpect-port='8080/tcp']"))
        marks = root("cat", MARKS, check=False)
        backup = root("cat", MARKS + ".bak", check=False)
        note("the mark removed from the page; the previous file kept as exposure.conf.bak",
             ok and not any(line.startswith("port 8080/tcp") for line in marks.splitlines())
             and "port 8080/tcp e2e test page" in backup, f"{title} -> {res}")

        # 5. DOCKER-USER: only the VPN may open new connections to the container.
        root("iptables", "-I", "DOCKER-USER", "-o", "docker0", "-m", "conntrack", "--ctstate", "NEW", "!", "-s",
             "10.8.0.0/24", "-j", "DROP")
        old = (state() or {}).get("generated")
        time.sleep(1.5)
        frame.locator("#sm-refresh").click()
        second = poll(page, lambda: (state() or {}).get("generated") != old and state(), 300)
        poll(page, lambda: "VPN only" in port_row(frame).inner_text(), 120)
        row = " ".join(port_row(frame).inner_text().split())
        p8080 = next((x for x in (second or {}).get("ports", []) if x["port"] == 8080 and x["proto"] == "tcp"), {})
        r4 = {c: v.get("result") for c, v in ((p8080.get("reach") or {}).get("4") or {}).items()}
        note("with a DOCKER-USER rule 8080/tcp is VPN only (spec 4.7)",
             "VPN only" in row and r4.get("internet") == "closed" and r4.get("vpn") == "open", f"{r4}; {row[:200]}")
        sshd = ((second or {}).get("sources") or {}).get("sshd") or {}
        note("sshd -T is read once /run/sshd exists" + (" (after the tmpfiles.d line of the page)" if privsep else ""),
             sshd.get("state") == "ok", json.dumps(sshd))
        shot(page, "docker-user")

        # 6. The regular check, set up from the page and switched off.
        title, res, ok, log = run_dialog(page, frame, frame.locator("#sm-timer-setup"), seconds=300)
        timer = (root("systemctl", "is-enabled", "cockpit-security-scan.timer", check=False),
                 root("systemctl", "is-active", "cockpit-security-scan.timer", check=False))
        note("regular check set up from the page: timer on", ok and timer == ("enabled", "active"),
             f"{title} -> {res}; timer {timer}; log {log.strip()[:120]}")
        poll(page, lambda: frame.locator("#sm-timer-off").count() == 1, 60)
        title, res, ok, log = run_dialog(page, frame, frame.locator("#sm-timer-off"))
        timer = root("systemctl", "is-enabled", "cockpit-security-scan.timer", check=False)
        note("regular check switched off from the page", ok and timer == "disabled", f"{title} -> {res}; timer {timer}")
        ctx.close()

        # 7. Without administrative access (a user without sudo, German browser).
        ctx, page = login(browser, E["PLAIN_USER"], E["PLAIN_PW"], locale="de-DE")
        page.wait_for_selector(FRAME, state="attached")
        check_menu(page, "de", "without administrative access, German, before the page is opened")
        frame, label = open_page(page)
        poll(page, lambda: "Anzeige ohne administrativen Zugriff" in text(frame, "#sm-status"), 60)
        note("without administrative access: the summary only, no action",
             "Anzeige ohne administrativen Zugriff" in text(frame, "#sm-status")
             and "Aus dem Internet erreichbar" in text(frame, "#sm-summary")
             and frame.locator("[data-expect-port], #sm-timer-setup").count() == 0,
             text(frame, "#sm-summary")[:200])
        shot(page, "no-admin")
        ctx.close()

        # 8. A link of the status (#/ssh, as the Status Board jumps) opens its tab.
        ctx, page = login(browser, E["ADMIN_USER"], E["ADMIN_PW"])
        admin_access(page, E["ADMIN_PW"])
        page.goto(URL + "/security#/ssh")
        frame = page.frame_locator(FRAME)
        frame.locator("#sm-sshd").wait_for()
        note("a link #/ssh opens the SSH tab with the configuration",
             frame.locator("#sm-tab-ssh").is_visible() and "passwordauthentication" in text(frame, "#sm-sshd"),
             text(frame, "#sm-sshd")[:160])
        shot(page, "ssh")

        # The Status Board jumps with cockpit.jump; Cockpit keeps the loaded page and only changes
        # its location: to another tab while it is shown, and into it while it is hidden.
        own = own_frame(page)
        own.evaluate("() => { window.smNotReloaded = true; }")

        def at_tab(tab, how):
            ok = poll(page, lambda: page.url.endswith("/security#/" + tab) and frame.locator("#sm-tab-" + tab).is_visible(), 30)
            kept = own.evaluate("() => window.smNotReloaded === true")
            note(f"a link {how}: the tab {tab}, the page not loaded again", bool(ok) and kept,
                 f"{page.url.split('9090', 1)[-1]}, {'not loaded again' if kept else 'loaded again'}")

        own.evaluate("p => cockpit.jump(p)", "/security#/logins")
        at_tab("logins", "while the page is shown (cockpit.jump)")
        # The link of a finding: the exposure tab, the port's row marked and brought into view.
        own.evaluate("p => cockpit.jump(p)", "/security#/exposure/8080-tcp")
        ok = poll(page, lambda: page.url.endswith("/security#/exposure/8080-tcp")
                  and frame.locator("#sm-tab-exposure").is_visible()
                  and port_row(frame).get_attribute("aria-current") == "location", 30)
        in_view = own.evaluate("() => { const r = document.getElementById('sm-port-tcp-8080').getBoundingClientRect();"
                               " return r.top >= 0 && r.top < window.innerHeight; }")
        kept = own.evaluate("() => window.smNotReloaded === true")
        note("a link to a port while the page is shown: the exposure tab, the row of 8080/tcp marked and in view",
             bool(ok) and in_view and kept, f"{page.url.split('9090', 1)[-1]}, in view {in_view}, "
                                            f"{'not loaded again' if kept else 'loaded again'}")
        shot(page, "port-link")
        own.evaluate("p => cockpit.jump(p)", "/system")
        poll(page, lambda: not page.locator(FRAME).is_visible(), 30)
        system = next((f for f in page.frames if f.name.endswith("/system")), own)
        system.evaluate("p => cockpit.jump(p)", "/security#/containers")
        at_tab("containers", "into the page while it is hidden")
        ctx.close()
        browser.close()


try:
    main()
except Exception as e:      # a step that could not even run counts as failed
    note("the session ran to its end", False, f"{type(e).__name__}: {e}"[:600])
    try:
        LAST["page"] and shot(LAST["page"], "failed")
    except Exception:
        pass
try:
    capture()
except Exception as e:
    print("capture failed:", e)

build = [x for x in errors if x[4] == "this build"]
ours = [x for x in build if OURS in x[1] + x[2]]
note("no JavaScript error and no failed request of the add-on's files or frame", not ours,
     "; ".join(f"{k} {u} {t[:120]}" for k, t, u, _, _ in ours)[:600])
other = [x for x in build if x not in ours and kind(x) not in BASELINE]
note("no other error in Cockpit than those it shows without the add-on", not other,
     "; ".join(f"{k} {u} {t[:120]}" for k, t, u, _, _ in other)[:600]
     or f"{len(build)} errors with this build, all of kinds Cockpit shows on its own")
report["errors"] = errors
with open(os.path.join(OUT, "report.json"), "w") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
md = ["## Security Monitor in a real Cockpit session", "", "| | |", "|---|---|"]
md += [f"| {k} | {v} |" for k, v in report["environment"].items()]
md += ["", "| Step | Result |", "|---|---|"]
md += [f"| {s['step']} | {'ok' if s['ok'] else 'FAILED'}{': ' + s['detail'] if s['detail'] else ''} |"
       for s in report["steps"]]
with open(os.path.join(OUT, "report.md"), "w") as f:
    f.write("\n".join(md) + "\n")
print("\n".join(md))
sys.exit(1 if failed else 0)
