// SPDX-License-Identifier: Apache-2.0
// The page against the state the helper writes for the scenarios (test/fixtures/state-*.json):
// tabs and links, the ports and their reasons, SSH, logins, containers, CrowdSec, the summary
// without administrative access, the first check by itself, Refresh, the timer and the marks,
// escaping, both languages; the status icon in Cockpit's menu and the start once the page is
// shown. Run: node test/page.test.js (jsdom: cd test && npm ci, or NODE_PATH).
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { boot, settle, state, show, proc, text, HELPER, FIX, STATUS_FILE } = require("./page");

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const GERMAN = /[äöüßÄÖÜ]|\b(und|nicht|oder|Aktualisieren|Stand|Sie|Anmeldung|erreichbar|Schlüssel)\b/;
const verbs = (calls) => calls.spawn.map((c) => c.argv.slice(1).join(" "));
const row = (d, proto, port) => d.getElementById(`sm-port-${proto}-${port}`);
// Arrays from the page's window are of another realm: compare their contents.
const same = (got, want, msg) => assert.deepStrictEqual(JSON.parse(JSON.stringify(got)), want, msg);

test("ufw-docker, English: the overview, the ports in order, Docker past UFW", async () => {
    const { d, calls } = boot();
    await settle();
    assert.deepStrictEqual(verbs(calls), ["show"]);
    assert.strictEqual(calls.spawn[0].opts.superuser, "try");
    assert.ok(calls.spawn[0].opts.environ.includes("SECURITY_LANG=en"));
    assert.strictEqual(d.getElementById("sm-tab-exposure").hidden, false);
    assert.strictEqual(d.getElementById("sm-tab-btn-crowdsec").hidden, true, "no CrowdSec here");
    const ov = text(d.getElementById("sm-ov"));
    assert.match(ov, /5 ports are reachable from the internet\./);
    assert.match(ov, /1 of them needs attention: ?8080\/tcp/);
    assert.match(ov, /UFW on, incoming by default: drop · 8 rules/);
    assert.match(ov, /Docker 28\.5\.1, firewall backend iptables/);
    assert.match(ov, /Regular check off Set up/);
    const ids = [...d.querySelectorAll(".sm-ports-table tbody tr")].map((r) => r.id);
    assert.strictEqual(ids[0], "sm-port-tcp-8080", "the warning first");
    assert.strictEqual(ids.length, 13);
    const r = row(d, "tcp", 8080);
    assert.strictEqual(r.dataset.state, "warning");
    assert.match(text(r), /container web nginx:1\.27-alpine · port 80 in the container/);
    assert.match(text(r), /Open to the internet Docker forwards it to the container; UFW does not apply here\./);
    const cells = [...r.querySelectorAll("td")].map((c) => text(c));
    assert.deepStrictEqual(cells.slice(2, 6), ["IPv4 yes · IPv6 no", "yes", "yes", "yes"]);
    const det = text(r.querySelector("details"));
    assert.match(det, /Docker forwards it to 172\.17\.0\.2:80/);
    assert.match(det, /UFW filters only what reaches the host itself/);
    assert.match(det, /DOCKER-USER has no rule for it\./);
    assert.match(det, /This family reaches docker-proxy on the host/);
    assert.match(det, /From the internet: not reachable: policy drop of chain INPUT, table ip6 filter/);
    assert.match(det, /What you can do \(by hand; this page sets no rule\):/);
    assert.match(det, /127\.0\.0\.1:8080:80/);
    assert.match(det, /iptables -I DOCKER-USER -o docker0 -m conntrack --ctstate NEW ! -s 10\.8\.0\.0\/24 -j DROP/);
    assert.ok(!/What you can do/.test(text(row(d, "tcp", 443))), "nothing to do for a usual public port");
    assert.ok(r.querySelector("[data-expect-port='8080/tcp']"), "a warning can be marked");
    assert.ok(!row(d, "tcp", 443).querySelector("[data-expect-port]"), "public and usual: nothing to mark");
    assert.ok(!row(d, "tcp", 22).querySelector("[data-expect-port]"), "not public: nothing to mark");
    assert.match(text(row(d, "tcp", 22)), /sshd ssh no yes no yes VPN only/);
    assert.match(text(row(d, "tcp", 6379)), /container cache redis · redis:7\.4 – yes – yes VPN only/);
    assert.match(text(d.getElementById("sm-unchecked-exposure")), /Rules this page cannot read/);
    assert.strictEqual(text(d.getElementById("sm-sig-version")), "Security Monitor 0.1.0");
    assert.strictEqual(text(d.getElementById("sm-sig-host")), "server");
    assert.ok(!GERMAN.test(text(d.body)), "no German on the English page: " + (text(d.body).match(GERMAN) || [])[0]);
    assert.ok(d.getElementById("sm-loading").hidden);
});

test("German: the same page in German", async () => {
    const { d, calls } = boot({ language: "de" });
    await settle();
    assert.strictEqual(d.documentElement.lang, "de");
    assert.ok(calls.spawn[0].opts.environ.includes("SECURITY_LANG=de"));
    assert.match(text(d.getElementById("sm-meta")), /^Stand vor 5 Minuten$/);
    assert.match(text(d.getElementById("sm-refresh")), /Aktualisieren/);
    assert.match(text(row(d, "tcp", 8080)), /Aus dem Internet offen Docker leitet ihn an den Container weiter; UFW gilt hier nicht\./);
    assert.match(text(d.getElementById("sm-ov")), /5 Ports sind aus dem Internet erreichbar\./);
    assert.strictEqual(text(d.getElementById("sm-tab-btn-exposure")), "Erreichbarkeit");
    assert.ok(!/\b(why|det|ov|col|reach|sub|label)\.[a-z]/.test(text(d.body)), "no raw text keys");
});

test("hetzner-open: protected by the Hetzner firewall, a source range, CrowdSec, a login from outside", async () => {
    const { d } = boot({ scenario: "hetzner-open" });
    await settle();
    const pg = row(d, "tcp", 5432);
    assert.strictEqual(pg.dataset.state, "ok");
    assert.match(text(pg), /Blocked by the Hetzner Cloud Firewall The host would let it in; Hetzner Cloud Firewall web stops it\./);
    assert.match(text(pg.querySelector("details")), /The Hetzner Cloud Firewall \(web\) does not let it through\./);
    assert.match(text(pg.querySelector("details")), /From the internet: reachable → not reachable/);
    assert.match(text(row(d, "tcp", 8443)), /Only from some addresses Allowed only from 198\.51\.100\.0\/24\./);
    assert.match(text(d.getElementById("sm-ov")), /Hetzner Cloud Firewall web, state of/);
    assert.match(text(d.getElementById("sm-ov")), /no rule stops new connections from the internet/);
    assert.strictEqual(d.getElementById("sm-tab-btn-crowdsec").hidden, false);
    const cs = text(d.getElementById("sm-crowdsec"));
    assert.match(cs, /1\.4\.6 is the old package from Ubuntu's archive/);
    assert.match(cs, /blocks only at the hook input/);
    assert.match(cs, /signals are shared with CrowdSec's central API/);
    assert.match(text(d.getElementById("sm-decisions")), /192\.0\.2\.50 crowdsecurity\/ssh-bf 3h37m crowdsec XX/);
    const lg = d.getElementById("sm-logins");
    assert.strictEqual(lg.querySelector(".az-card__header .az-label").dataset.state, "warning");
    assert.match(text(lg), /198\.51\.100\.20 internet publickey/);
    assert.match(text(d.getElementById("sm-failed")), /8 attempts from 3 sources in 14 days/);
    assert.match(text(d.getElementById("sm-sshd")), /passwordauthentication yes Warning Passwords are accepted\./);
});

test("hetzner-open without a token: only rules outside the host could protect the ports", async () => {
    const st = state("hetzner-open");
    st.firewall.hetzner = { configured: false };
    st.ports.forEach((p) => {
        if (p.why === "hetzner") { p.state = "warning"; p.why = "outside-only"; }
    });
    const { d } = boot({ view: show(st) });
    await settle();
    const pg = row(d, "tcp", 5432);
    assert.match(text(pg), /Only rules outside this host could protect it This host lets new connections in; no firewall outside it is known\./);
    assert.match(text(pg.querySelector("details")), /none is known \(no Hetzner token\): not checkable/);
    assert.match(text(d.getElementById("sm-ov")), /not set up \(a read-only token in \/etc\/cockpit-security-monitor\/hetzner\.token/);
});

test("nft-native: sshd -T without /run/sshd, a DSA key, containers, a restricted port", async () => {
    const { d } = boot({ scenario: "nft-native", location: ["ssh"] });
    await settle();
    assert.strictEqual(d.getElementById("sm-tab-ssh").hidden, false, "the link opens its tab");
    assert.strictEqual(d.getElementById("sm-tab-exposure").hidden, true);
    assert.strictEqual(d.getElementById("sm-tab-btn-ssh").getAttribute("aria-selected"), "true");
    const sshd = text(d.getElementById("sm-sshd"));
    assert.match(sshd, /sshd -T fails on this server/);
    assert.match(sshd, /echo 'd \/run\/sshd 0755 root root -' > \/etc\/tmpfiles\.d\/sshd-privsep\.conf/);
    const keys = text(d.getElementById("sm-keys"));
    assert.match(keys, /ci: \/home\/ci\/\.ssh\/authorized_keys, mode 644/);
    assert.match(keys, /others can change its folder/);
    assert.match(keys, /DSA: no longer accepted by current OpenSSH/);
    assert.match(text(d.getElementById("sm-unchecked-ssh")), /Match blocks change these values .*20-vpn\.conf/);
    assert.match(text(row(d, "tcp", 60001)), /Only from some addresses Allowed only from 192\.0\.2\.0\/24\./);
    assert.match(text(row(d, "tcp", 60001).querySelector("details")),
                 /From the internet: reachable only from 192\.0\.2\.0\/24: everyone else stopped by policy drop of chain input, table inet filter; .*rule tcp dport 60000-60010 ip saddr 192\.0\.2\.0\/24 accept in chain input, table inet filter/);
    assert.match(text(row(d, "tcp", 9100)), /container monitor/);
    const runner = d.getElementById("sm-container-runner");
    assert.match(text(runner), /Docker socket mounted: full access to Docker/);
    assert.ok(runner.querySelector("[data-expect-container='runner'][data-kind='docker-socket']"));
    assert.ok(!runner.querySelector("[data-kind='root-user'] button"), "notes are not offered for marking");
});

test("ufw-docker: a locked account whose keys still log in, a journal shorter than 14 days", async () => {
    const { d } = boot({ location: ["ssh"] });
    await settle();
    const blocks = [...d.getElementById("sm-keys").querySelectorAll(".sm-keyfile")];
    const alex = blocks.find((b) => /^alex:/.test(text(b)));
    assert.strictEqual(alex.dataset.state, "warning");
    assert.match(text(alex.querySelector(".sm-account")),
                 /^Password locked The password of alex is locked \(passwd -l\), but these keys still log in: with UsePAM yes, sshd does not check the lock\. usermod --expiredate 1 alex closes the account for keys too\.$/);
    assert.ok(!blocks.find((b) => /^root:/.test(text(b))).querySelector(".sm-account"), "root never had a password: no lock");
    assert.match(text(d.getElementById("sm-journal-start")),
                 /^The journal begins on 11 October: older entries are gone, so the lists on this tab cover less than 14 days\.$/);
    const { d: de } = boot({ language: "de", location: ["logins"] });
    await settle();
    assert.match(text(de.getElementById("sm-journal-start")), /^Das Journal beginnt am 11\. Oktober: Ältere Einträge sind gelöscht/);
    assert.match(text(de.querySelector(".sm-account")), /Das Passwort von alex ist gesperrt \(passwd -l\)/);
    const { d: h } = boot({ scenario: "hetzner-open" });
    await settle();
    assert.strictEqual(h.getElementById("sm-journal-start"), null, "start unknown: no note");
});

test("ports only some addresses reach are counted apart in the overview", async () => {
    const { d } = boot({ scenario: "nft-native" });
    await settle();
    const ov = text(d.getElementById("sm-ov"));
    assert.match(ov, /4 ports are reachable from the internet\./);
    assert.match(ov, /1 port is reachable only from some addresses on the internet\./);
    const st = state("nft-native");
    st.ports.forEach((p) => ["4", "6"].forEach((f) => {
        if (p.reach[f].internet.result === "open") p.reach[f].internet.result = "closed";
    }));
    const { d: only } = boot({ view: show(st) });
    await settle();
    const ov2 = text(only.getElementById("sm-ov"));
    assert.ok(!/reachable from the internet\.|No port is reachable/.test(ov2), ov2);
    assert.match(ov2, /1 port is reachable only from some addresses on the internet\./);
});

test("recorded-services: a port only an ipset reaches names the rule that keeps everyone else out", async () => {
    const { d } = boot({ scenario: "recorded-services" });
    await settle();
    const det = row(d, "udp", 21116).querySelector("details");
    assert.match(text(det), /From the internet: reachable only from ipset germany: everyone else stopped by rule -p udp -m udp --dport 21116 -m set ! --match-set germany src -j DROP in chain DOCKER-USER, table ip filter \(Docker\); /);
    assert.match(text(det), /rule -d 172\.20\.0\.3\/32 .*-j ACCEPT in chain DOCKER, table ip filter/, "and the rule that lets the members in");
    const code = [...det.querySelectorAll("li code")].map((c) => c.textContent);
    assert.strictEqual(code[0], "-p udp -m udp --dport 21116 -m set ! --match-set germany src -j DROP", "the limiting rule first, as code");
    assert.ok(!/everyone else/.test(text(row(d, "tcp", 443).querySelector("details"))), "only where the result is restricted");
    const { d: de } = boot({ scenario: "recorded-services", language: "de" });
    await settle();
    assert.match(text(row(de, "udp", 21116).querySelector("details")),
                 /Aus dem Internet: erreichbar nur von ipset germany: alle anderen abgewiesen durch Regel -p udp -m udp --dport 21116 -m set ! --match-set germany src -j DROP in Kette DOCKER-USER, Tabelle ip filter/);
    const { d: nft } = boot({ scenario: "nft-native", language: "de" });
    await settle();
    assert.match(text(row(nft, "tcp", 60001).querySelector("details")),
                 /erreichbar nur von 192\.0\.2\.0\/24: alle anderen abgewiesen durch Policy drop von Kette input, Tabelle inet filter/);
});

test("links follow the location while the page is open", async () => {
    const { d, listeners, w } = boot();
    await settle();
    w.cockpit.location.path = ["logins"];
    listeners.locationchanged.forEach((f) => f());
    assert.strictEqual(d.getElementById("sm-tab-logins").hidden, false);
    w.cockpit.location.path = ["nonsense"];
    listeners.locationchanged.forEach((f) => f());
    assert.strictEqual(d.getElementById("sm-tab-logins").hidden, false, "an unknown place changes nothing");
    d.getElementById("sm-tab-btn-containers").click();
    assert.strictEqual(d.getElementById("sm-tab-containers").hidden, false);
});

test("tabs by keyboard", async () => {
    const { d, calls } = boot();
    await settle();
    const nav = d.getElementById("sm-tabs");
    nav.dispatchEvent(new d.defaultView.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
    assert.strictEqual(d.getElementById("sm-tab-ssh").hidden, false);
    nav.dispatchEvent(new d.defaultView.KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
    nav.dispatchEvent(new d.defaultView.KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
    assert.strictEqual(d.getElementById("sm-tab-containers").hidden, false, "wraps around past the hidden CrowdSec tab");
    same(calls.go, [["ssh"], ["exposure"], ["containers"]]);
});

test("without administrative access: the summary only, no actions", async () => {
    const { d, calls } = boot({ admin: false, language: "de" });
    await settle();
    assert.deepStrictEqual(verbs(calls), ["show", "status --lang de"]);
    assert.match(text(d.getElementById("sm-status")), /Anzeige ohne administrativen Zugriff/);
    assert.strictEqual(d.getElementById("sm-tabs").hidden, true);
    assert.strictEqual(d.getElementById("sm-summary").hidden, false);
    const sum = text(d.getElementById("sm-summary"));
    assert.match(sum, /Aus dem Internet erreichbar 5/);
    assert.match(sum, /Docker-Socket: runner/);
    assert.ok(!d.querySelector("[data-expect-port], #sm-timer-setup"));
    d.getElementById("sm-refresh").click();
    await settle();
    assert.ok(!verbs(calls).includes("scan"), "Refresh only reads again");
});

test("a fresh install with admin: one check by itself, then the state", async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const { d, calls, box } = boot({
        view: show(null),
        onSpawn: (verb, opts, b) => {
            if (verb !== "scan") return null;
            assert.strictEqual(opts.superuser, "require");
            return proc("", { gate: gate.then(() => { b.view = show(state("ufw-docker")); }) });
        },
    });
    for (let i = 0; i < 50 && !verbs(calls).includes("scan"); i++) await new Promise((r) => setImmediate(r));
    assert.strictEqual(verbs(calls).filter((v) => v === "scan").length, 1);
    assert.ok(!d.getElementById("sm-loading").hidden, "the loading block while the first check runs");
    assert.match(text(d.getElementById("sm-refresh")), /Checking/);
    release();
    await settle();
    assert.ok(box.view.state);
    assert.ok(d.getElementById("sm-loading").hidden);
    assert.ok(row(d, "tcp", 8080));
    assert.strictEqual(verbs(calls).filter((v) => v === "scan").length, 1, "only once");
});

test("Refresh: a check as administrator; failures and a busy service as messages", async () => {
    let fail = null;
    const { d, calls } = boot({ onSpawn: (verb) => (verb === "scan" ? proc("", { fail }) : null) });
    await settle();
    d.getElementById("sm-refresh").click();
    await settle();
    const scan = calls.spawn.find((c) => c.argv[1] === "scan");
    assert.strictEqual(scan.opts.superuser, "require");
    assert.strictEqual(text(d.getElementById("sm-status")), "");
    fail = { exit_status: 1 };
    d.getElementById("sm-refresh").click();
    await settle();
    assert.match(text(d.getElementById("sm-status")), /The check failed/);
    fail = { exit_status: 75 };
    d.getElementById("sm-refresh").click();
    await settle();
    assert.match(text(d.getElementById("sm-status")), /A check is running already/);
    assert.ok(!d.getElementById("sm-refresh").disabled);
});

test("mark a port as expected: the dialog, the note, the call, then the state again", async () => {
    const { d, calls, box } = boot();
    await settle();
    row(d, "tcp", 8080).querySelector("[data-expect-port]").click();
    const dlg = d.getElementById("sm-dialog");
    assert.ok(dlg.hasAttribute("open"));
    assert.strictEqual(text(d.getElementById("sm-dialog-title")), "Mark 8080/tcp as expected");
    assert.match(text(d.getElementById("sm-dialog-desc")), /never a firewall rule/);
    assert.strictEqual(d.getElementById("sm-dialog-note-field").hidden, false);
    d.getElementById("sm-dialog-input").value = "  test page\u0007 for the office ";
    const marked = state("ufw-docker");
    const p = marked.ports.find((x) => x.port === 8080);
    p.expected = "test page for the office";
    p.base_state = p.state;
    p.state = "info";
    box.view = show(marked);
    d.getElementById("sm-dialog-confirm").click();
    await settle();
    const call = calls.spawn.find((c) => c.argv[1] === "expect");
    same(call.argv, [HELPER, "expect", "port", "8080/tcp", "--note", "test page  for the office"]);
    assert.strictEqual(call.opts.superuser, "require");
    assert.match(text(d.getElementById("sm-dialog-result")), /Done\./);
    d.getElementById("sm-dialog-cancel").click();
    assert.ok(!dlg.hasAttribute("open"));
    const r = row(d, "tcp", 8080);
    assert.match(text(r), /Marked as expected Note: test page for the office/);
    r.querySelector("[data-unexpect-port='8080/tcp']").click();
    assert.strictEqual(d.getElementById("sm-dialog-note-field").hidden, true);
    d.getElementById("sm-dialog-confirm").click();
    await settle();
    same(calls.spawn.find((c) => c.argv[1] === "unexpect").argv, [HELPER, "unexpect", "port", "8080/tcp"]);
});

test("mark a container finding, and a failing call", async () => {
    const { d, calls } = boot({ scenario: "nft-native",
                                onSpawn: (verb) => (verb.startsWith("expect") ? proc("", { fail: { exit_status: 5 } }) : null) });
    await settle();
    d.querySelector("[data-expect-container='runner'][data-kind='privileged']").click();
    assert.strictEqual(text(d.getElementById("sm-dialog-title")), "Mark “privileged” of runner as expected");
    d.getElementById("sm-dialog-confirm").click();
    await settle();
    same(calls.spawn.find((c) => c.argv[1] === "expect").argv, [HELPER, "expect", "container", "runner", "privileged"]);
    assert.match(text(d.getElementById("sm-dialog-result")), /Failed \(exit code 5\)\./);
});

test("the regular check: set up from the overview", async () => {
    const { d, calls, box } = boot();
    await settle();
    d.getElementById("sm-timer-setup").click();
    assert.strictEqual(text(d.getElementById("sm-dialog-title")), "Set up the regular check");
    box.view = show(state("ufw-docker"), { timer: "active", next: "2026-10-20T12:19:00Z" });
    d.getElementById("sm-dialog-confirm").click();
    await settle();
    same(calls.spawn.find((c) => c.argv[1] === "install").argv, [HELPER, "install", "timer"]);
    assert.match(text(d.getElementById("sm-dialog-log")), /ok/);
    assert.match(text(d.getElementById("sm-ov")), /every 15 minutes, next on .* Switch off/);
});

test("page messages: an old state, untrusted marks, a newer format", async () => {
    const st = state("ufw-docker");
    st.format = 2;
    const { d } = boot({ view: show(st, { marks_problem: "untrusted" }), now: "2026-10-20T15:00:00Z" });
    await settle();
    const msg = text(d.getElementById("sm-status"));
    assert.match(msg, /The last check is 3 hours old/);
    assert.match(msg, /\/etc\/cockpit-security-monitor\/exposure\.conf does not belong to root/);
    assert.match(msg, /The state comes from a newer version/);
    const { d: d2 } = boot({ view: show(state("ufw-docker"), { marks_problem: "lines 3,4" }) });
    await settle();
    assert.match(text(d2.getElementById("sm-status")), /could not be read and do not count \(lines 3,4\)/);
});

test("values from the system are text, never markup", async () => {
    const st = state("nft-native");
    const evil = '<img src=x onerror="window.__pwned=1">`code`';
    st.containers.items[0].name = evil;
    st.containers.items[0].image = evil;
    st.ports[0].service.processes = [evil];
    st.ssh.keys[0].keys[0].comment = evil;
    st.ports[0].reach["4"].local.steps = [{ chain: { chain: evil, family: "ip", table: "filter", policy: "drop" }, result: "accept",
        rule: { chain: evil, family: "ip", table: "filter", text: evil, owner: null }, policy: false }];
    const { d, w } = boot({ view: show(st) });
    await settle();
    for (const k of ["exposure", "ssh", "containers"]) {
        d.getElementById("sm-tab-btn-" + k).click();
        d.querySelectorAll("details").forEach((x) => { x.open = true; });
    }
    assert.strictEqual(d.querySelectorAll("img").length, 0);
    assert.strictEqual(w.__pwned, undefined);
    assert.ok(text(d.body).includes("<img src=x onerror="), "shown as text");
    assert.ok(!d.querySelector("[data-expect-container^='<img']"), "no mark for a name that is no container name");
});

test("unknown sources are named under Not checked", async () => {
    const st = state("ufw-docker");
    st.sources.rules = { state: "needs-root" };
    st.sources.journal = { state: "error", error: "journal corrupt" };
    const { d } = boot({ view: show(st) });
    await settle();
    assert.match(text(d.getElementById("sm-unchecked-exposure")), /Packet filter: needs administrative access\./);
    d.getElementById("sm-tab-btn-logins").click();
    assert.match(text(d.getElementById("sm-unchecked-logins")), /Journal: failed: journal corrupt\./);
});

// --- The status icon in Cockpit's menu (menu-status.js) and the hidden start ---
const statusFixture = (name) => JSON.parse(fs.readFileSync(path.join(FIX, "status-" + name + ".json"), "utf8"));
const SCENARIOS = fs.readdirSync(FIX).filter((f) => /^status-.+\.json$/.test(f)).map((f) => f.slice("status-".length, -".json".length));
const lastNote = (calls) => (calls.notes.length ? calls.notes[calls.notes.length - 1][1].page_status : "unset");
const TYPES = { danger: "error", warning: "warning", info: "info" };
const plain = (o) => JSON.parse(JSON.stringify(o));
const atMinutes = (st, m) => new Date(Date.parse(st.checked_at) + m * 60e3).toISOString();

test("menu icon: the state of status.json, the summary in the page's language", async () => {
    assert.ok(SCENARIOS.length >= 7, "every scenario: " + SCENARIOS.join(", "));
    for (const name of SCENARIOS) {
        const st = statusFixture(name);
        for (const language of ["en", "de"]) {
            // The scenario's time, half an hour on: not out of date.
            const { calls } = boot({ language, now: atMinutes(st, 30), statusFile: JSON.stringify(st) });
            await settle();
            const summary = language === "de" ? st.i18n.de.summary : st.summary;
            same(lastNote(calls), TYPES[st.state] ? { type: TYPES[st.state], title: summary } : null, `${name} ${language}`);
            assert.strictEqual(calls.notes.length, 1, "sent once");
            assert.strictEqual(calls.notes[0][0], "notify");
        }
    }
    const { calls } = boot();
    await settle();
    same(calls.notes, [["notify", { page_status: null }]], "no status.json: no icon, but sent");
    const broken = boot({ statusFile: "{broken" });
    await settle();
    assert.strictEqual(lastNote(broken.calls), null, "unreadable: no icon");
});

test("menu icon: judged as the Status Board does", async () => {
    const st = statusFixture("ufw-docker");
    const at = Date.parse(st.checked_at);
    const en = boot({ now: atMinutes(st, 10) });
    const de = boot({ language: "de", now: atMinutes(st, 10) });
    await settle();
    const icon = (doc, minutes, page = en) => page.w.SecurityMonitorMenuStatus.statusOf(doc, at + minutes * 60e3);
    // Never better than an item.
    const ok = plain(st);
    ok.state = "ok";
    ok.items.forEach((i) => { i.state = "ok"; });
    assert.strictEqual(icon(ok, 10), null, "all OK: no icon");
    const worse = plain(ok);
    worse.items[2].state = "danger";
    same(icon(worse, 10), { type: "error", title: st.summary });
    const info = plain(ok);
    info.items[0].state = "info";
    same(icon(info, 10), { type: "info", title: st.summary });
    assert.strictEqual(icon({ ...ok, state: "none", items: ok.items.map((i) => ({ ...i, state: "none" })) }, 10), null,
                       "not checked yet: no icon");
    // An item older than its stale_after (an hour) is at least a warning; the tooltip says since when.
    assert.strictEqual(icon(ok, 59), null, "59 minutes: nothing to show");
    const when = (loc) => new Date(at).toLocaleString(loc, { dateStyle: "medium", timeStyle: "short" });
    same(icon(ok, 61), { type: "warning", title: `${st.summary} (as of ${when("en-GB")}, out of date)` });
    same(icon(ok, 61, de), { type: "warning", title: `${st.i18n.de.summary} (Stand ${when("de-DE")}, veraltet)` });
    assert.strictEqual(icon(st, 120).type, "error", "a danger stays a danger when out of date");
    // What the board ignores.
    const odd = plain(ok);
    odd.items.forEach((i) => { i.checked_at = i.checked_at.replace("Z", ""); });
    assert.strictEqual(icon(odd, 120), null, "a time without a zone is not judged");
    [null, 3, "x", { ...st, schema: 2 }, { ...st, items: "x" }].forEach((d) => assert.strictEqual(icon(d, 10), null));
    assert.strictEqual(icon({ ...st, summary: "x".repeat(300), i18n: undefined }, 10).title.length, 200, "cut as the board cuts it");
});

test("menu icon: checked again the moment an item turns out of date", async () => {
    const st = statusFixture("ufw-docker");
    st.state = "ok";
    st.items.forEach((i) => { i.state = "ok"; });
    const at = Date.parse(st.checked_at);
    const r = boot({ now: atMinutes(st, 20) });
    await settle();
    const timers = [];
    r.w.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
    r.watchers.find((x) => x.p === STATUS_FILE && !x.json).cb(JSON.stringify(st), "tag-2");
    assert.strictEqual(lastNote(r.calls), null);
    same(timers.map((x) => x.ms), [40 * 60e3 + 1000], "again when it is an hour old");
    r.w.Date.now = () => at + 3600e3 + 1000;
    timers[0].fn();
    assert.strictEqual(lastNote(r.calls).type, "warning", "out of date: a warning");
});

test("preloaded hidden: only the icon; the page starts once it is shown", async () => {
    const st = statusFixture("ufw-docker");
    const r = boot({ hidden: true, view: show(null), now: atMinutes(st, 10), statusFile: JSON.stringify(st) });
    await settle();
    same(lastNote(r.calls), { type: "error", title: st.summary });
    same([r.calls.spawn.length, r.calls.reads], [0, []], "hidden: no helper, no other file");
    same(r.watchers.map((x) => x.p), [STATUS_FILE], "hidden: only the icon's watch");
    assert.strictEqual(text(r.d.getElementById("sm-sig-version")), "Security Monitor", "hidden: not started");
    r.hint(false);
    await settle();
    same(verbs(r.calls), ["show", "scan", "show"], "shown: the state, and only now the first check by itself");
    assert.strictEqual(text(r.d.getElementById("sm-sig-version")), "Security Monitor 0.1.0");
    same(r.calls.reads, ["/etc/hostname"]);
    r.hint(true);
    r.hint(false);
    await settle();
    same(verbs(r.calls), ["show", "scan", "show"], "shown again: no second start");
});

test("a link that comes while the page is hidden: its tab once shown", async () => {
    const r = boot({ hidden: true });
    await settle();
    r.w.cockpit.location.path = ["ssh"];
    r.listeners.locationchanged.forEach((f) => f());
    r.hint(false);
    await settle();
    assert.strictEqual(r.d.getElementById("sm-tab-ssh").hidden, false);
    assert.strictEqual(r.d.getElementById("sm-tab-exposure").hidden, true);
    assert.match(text(r.d.getElementById("sm-sshd")), /PasswordAuthentication/i);
});

(async () => {
    let failed = 0;
    for (const { name, fn } of tests) {
        try {
            await fn();
            console.log("PASS  " + name);
        } catch (e) {
            failed++;
            console.log("FAIL  " + name + "\n" + (e && e.stack || e));
        }
    }
    console.log(failed ? `${failed} of ${tests.length} failed` : `all ${tests.length} passed`);
    // Now, not when the pages' timers (the menu icon's re-check) have run out.
    process.exit(failed ? 1 : 0);
})();
