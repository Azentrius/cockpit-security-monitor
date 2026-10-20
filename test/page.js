// SPDX-License-Identifier: Apache-2.0
// The real page (icons.js, i18n.js, menu-status.js, security.js) in jsdom with a scripted
// Cockpit stub, for the page tests. boot() returns the window, the calls the page made and the
// stub's state; settle() waits until every stubbed answer has arrived and the page has handled it.
"use strict";
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const PLUGIN = path.join(__dirname, "..", "plugin");
const FIX = path.join(__dirname, "fixtures");
const html = fs.readFileSync(path.join(PLUGIN, "index.html"), "utf8");
const js = ["icons.js", "i18n.js", "menu-status.js", "security.js"].map((f) => fs.readFileSync(path.join(PLUGIN, f), "utf8")).join("\n");
const NOW = "2026-10-20T12:05:00Z";
const HELPER = "/usr/lib/cockpit-security-monitor/security.py";
const STATUS_FILE = "/var/lib/cockpit-security-monitor/status.json";

function state(name) {
    return JSON.parse(fs.readFileSync(path.join(FIX, "state-" + name + ".json"), "utf8"));
}
function statusDoc(name, lang) {
    const st = JSON.parse(fs.readFileSync(path.join(FIX, "status-" + name + ".json"), "utf8"));
    const out = Object.assign({}, st);
    delete out.i18n;
    if (lang === "de") {
        const de = st.i18n.de;
        out.summary = de.summary;
        out.items = st.items.map((i) => Object.assign({}, i, de.items[i.id] || {}));
    }
    return out;
}
function show(st, extra) {
    return Object.assign({ root: true, state: st, marks_problem: null, marks_file: "/etc/cockpit-security-monitor/exposure.conf",
                           timer: "inactive", next: null, running: false, hetzner_token: false }, extra || {});
}

const pending = new Set();
function track(p) {
    const done = p.then(() => {}, () => {});
    pending.add(done);
    done.then(() => pending.delete(done));
    return p;
}
async function settle() {
    for (let round = 0; round < 500; round++) {
        if (pending.size) await Promise.all([...pending]);
        await new Promise((r) => setImmediate(r));
        if (!pending.size) return;
    }
    throw new Error("the page did not settle: helper calls keep coming");
}
// A stubbed process: resolves (or rejects with `fail`) after streaming `chunks`;
// `gate` holds the answer back until the test releases it.
function proc(out, { chunks = [], fail = null, gate = null } = {}) {
    let cb = null;
    const p = new Promise((resolve, reject) => {
        const go = () => setImmediate(() => {
            chunks.forEach((c) => cb && cb(c));
            fail ? reject(fail) : resolve(out);
        });
        if (gate) gate.then(go); else go();
    });
    p.stream = (f) => { cb = f; return p; };
    return track(p);
}

function boot({ language = "en", scenario = "ufw-docker", view = undefined, admin = true, now = NOW, onSpawn = null,
                location = [], hidden = false, statusFile = null } = {}) {
    const dom = new JSDOM(html, { runScripts: "outside-only", url: "https://localhost:9090/security/" });
    const w = dom.window;
    w.document.querySelectorAll("script").forEach((s) => s.remove());
    w.HTMLDialogElement.prototype.showModal = function () { this.setAttribute("open", ""); };
    w.HTMLDialogElement.prototype.close = function () { this.removeAttribute("open"); };
    w.Element.prototype.scrollIntoView = function () { w.__scrolled = this.id; };
    w.Date.now = () => Date.parse(now);
    const calls = { spawn: [], reads: [], go: [], notes: [] };
    const box = { view: view === undefined ? show(state(scenario)) : view };
    const watchers = [];
    const listeners = {};
    w.cockpit = {
        language,
        location: { path: location, go(p) { calls.go.push(p); this.path = p; } },
        hidden,
        addEventListener(ev, cb) { (listeners[ev] = listeners[ev] || []).push(cb); },
        removeEventListener(ev, cb) { listeners[ev] = (listeners[ev] || []).filter((x) => x !== cb); },
        file(p, opts) {
            return {
                read() { calls.reads.push(p); return track(Promise.resolve(p === "/etc/hostname" ? "server\n" : null)); },
                // Raw text for menu-status.js; security.js asks with syntax JSON and only looks at the tag.
                watch(cb) {
                    watchers.push({ p, cb, json: !!(opts && opts.syntax) });
                    cb(p === STATUS_FILE && !(opts && opts.syntax) ? statusFile : null, "tag-1");
                },
            };
        },
        spawn(argv, opts) {
            calls.spawn.push({ argv: argv.slice(), opts: opts || {} });
            const verb = argv.slice(1).join(" ");
            if (onSpawn) {
                const r = onSpawn(verb, opts || {}, box, argv);
                if (r) return r;
            }
            if (verb === "show") {
                if (!admin) return proc("", { fail: { exit_status: 77, message: "This needs administrative access." } });
                return proc(JSON.stringify(typeof box.view === "function" ? box.view() : box.view));
            }
            if (verb.startsWith("status")) return proc(JSON.stringify(statusDoc(scenario, argv[3])));
            return proc("", { chunks: ["ok\n"] });
        },
        jump() {},
        transport: { wait() {}, control(c, o) { calls.notes.push([c, JSON.parse(JSON.stringify(o))]); } },
    };
    w.eval(js);
    // The shell's hint: cockpit.js changes cockpit.hidden and tells its listeners.
    const hint = (h) => { w.cockpit.hidden = h; (listeners.visibilitychange || []).slice().forEach((cb) => cb()); };
    return { w, d: w.document, calls, box, watchers, listeners, hint };
}

// The visible text, with spaces between cells and items as a reader sees them.
function text(el) {
    if (!el) return "";
    const c = el.cloneNode(true);
    c.querySelectorAll("td, th, li, dt, dd, p, summary, button, span.az-label, span.sm-sub, span.az-cell-sub").forEach((x) => { x.prepend(" "); x.append(" "); });
    return c.textContent.replace(/\s+/g, " ").trim();
}

module.exports = { boot, settle, state, statusDoc, show, proc, text, NOW, HELPER, PLUGIN, FIX, STATUS_FILE };
