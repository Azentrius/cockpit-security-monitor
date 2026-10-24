// SPDX-License-Identifier: Apache-2.0
/* Security Monitor, a Cockpit add-on: what is reachable from where on this
 * server, who logs in, and what weakens the boundary of its containers.
 *
 *   show    -> cockpit.spawn(security.py show), superuser "try"     the state with the marks (root)
 *   status  -> cockpit.spawn(security.py status --lang xx)          the summary without root
 *   refresh -> cockpit.spawn(security.py scan), superuser "require" runs the scan service, waits
 *   timer   -> security.py install|remove timer                     through the dialog
 *   marks   -> security.py expect|unexpect …                        through the dialog
 *   watch   -> cockpit.file(/var/lib/cockpit-security-monitor/status.json)  written by every scan and mark
 *
 * menu-status.js runs first: it sets the status icon in Cockpit's menu, also while
 * Cockpit keeps the page loaded hidden, and says when the page is shown; only then
 * does this file call the helper.
 *
 * The page only reads. It can set up or switch off the add-on's own timer and
 * mark a finding as expected (the add-on's own file); both are shown first and
 * confirmed. Texts: plugin/i18n.js. Everything from the system reaches the page
 * as text (h(), textContent), never as markup. No build step, no framework, no
 * external requests.
 */

(function () {
    "use strict";

    // --- Configuration -----------------------------------------------------
    // The one place for the version (SemVer). index.html loads every script and
    // stylesheet with ?v=VERSION; tools/check-version.sh keeps them in step.
    const VERSION = "0.3.1";
    const HELPER = "/usr/lib/cockpit-security-monitor/security.py";
    const STATUS_PATH = "/var/lib/cockpit-security-monitor/status.json";
    const MARKS_FILE = "/etc/cockpit-security-monitor/exposure.conf";
    const FORMAT = 1;          // newest state.json format this page knows
    const STALE_MIN = 60;      // a state older than this gets a hint (the board calls it out of date)
    const TABS = ["exposure", "ssh", "logins", "containers", "crowdsec", "fail2ban"];
    const CLASSES = ["internet", "vpn", "private", "local"];
    const ORDER = { none: 0, ok: 1, info: 2, warning: 3, danger: 4 };
    const ICONS = { none: "ban", ok: "check-circle", info: "info-circle", warning: "exclamation-triangle",
                    danger: "exclamation-circle" };
    const LABEL_CLASS = { none: "az-label", ok: "az-label az-label--success", info: "az-label az-label--info",
                          warning: "az-label az-label--warning", danger: "az-label az-label--danger" };

    // --- i18n --------------------------------------------------------------
    const I18N = window.SecurityMonitorI18n;
    const LANG = /^de([-_]|$)/i.test(String(cockpit.language || "")) ? "de" : "en";
    const LOCALE = LANG === "de" ? "de-DE" : "en-GB";

    function t(key, vars) {
        let s = I18N[LANG][key];
        if (s === undefined) s = I18N.en[key];
        if (s === undefined) return key;
        if (typeof s === "object") s = (vars && vars.n === 1) ? s.one : s.other;
        return s.replace(/\{(\w+)\}/g, (m, k) => (vars && k in vars ? String(vars[k]) : m));
    }

    // --- DOM, text only ------------------------------------------------------
    // h(tag, attrs, ...children): children are nodes or strings (as text).
    function h(tag, attrs) {
        const el = document.createElement(tag);
        Object.keys(attrs || {}).forEach((k) => {
            const v = attrs[k];
            if (v === null || v === undefined || v === false) return;
            if (k === "class") el.className = v;
            else if (k === "text") el.textContent = v;
            else if (k === "hidden") el.hidden = !!v;
            else if (k === "disabled") el.disabled = !!v;
            else el.setAttribute(k, v === true ? "" : String(v));
        });
        for (let i = 2; i < arguments.length; i++) add(el, arguments[i]);
        return el;
    }
    function add(el, kid) {
        if (kid === null || kid === undefined || kid === false) return;
        if (Array.isArray(kid)) { kid.forEach((k) => add(el, k)); return; }
        el.appendChild(typeof kid === "string" || typeof kid === "number" ? document.createTextNode(String(kid)) : kid);
    }
    function fill(el) {
        while (el.firstChild) el.removeChild(el.firstChild);
        for (let i = 1; i < arguments.length; i++) add(el, arguments[i]);
        return el;
    }
    // A translated text: `…` becomes <code>; values from the system cannot open or close one.
    function rich(text) {
        const frag = document.createDocumentFragment();
        String(text).split("`").forEach((part, i) => {
            if (!part) return;
            frag.appendChild(i % 2 ? h("code", { text: part }) : document.createTextNode(part));
        });
        return frag;
    }
    function tr(key, vars) {
        const v = {};
        // A number stays one (it picks the plural, and holds no backtick).
        Object.keys(vars || {}).forEach((k) => {
            v[k] = typeof vars[k] === "number" ? vars[k] : String(vars[k] == null ? "" : vars[k]).replace(/`/g, "'");
        });
        return rich(t(key, v));
    }
    const SVG = "http://www.w3.org/2000/svg";
    function icon(name) {
        const def = (window.AzIcons || {})[name];
        if (!def) return null;
        const svg = document.createElementNS(SVG, "svg");
        svg.setAttribute("class", "az-icon");
        svg.setAttribute("viewBox", def.viewBox);
        svg.setAttribute("aria-hidden", "true");
        svg.setAttribute("focusable", "false");
        svg.setAttribute("data-icon", name);
        const path = document.createElementNS(SVG, "path");
        path.setAttribute("d", def.d);
        svg.appendChild(path);
        return svg;
    }
    function label(state, text) {
        const s = ORDER[state] === undefined ? "none" : state;
        return h("span", { class: LABEL_CLASS[s], "data-state": s }, icon(ICONS[s]), text || t("label." + s));
    }
    function code(s) { return h("code", { text: String(s) }); }
    function btn(cls, iconName, text, attrs) {
        return h("button", Object.assign({ type: "button", class: "az-btn " + cls }, attrs || {}),
            iconName ? icon(iconName) : null, h("span", { text }));
    }
    function alertBox(kind, title, body) {
        const ic = kind === "danger" ? "exclamation-circle" : kind === "warning" ? "exclamation-triangle" : "info-circle";
        return h("div", { class: "az-alert" + (kind === "info" ? "" : " az-alert--" + kind), role: kind === "danger" ? "alert" : "status" },
            h("span", { class: "az-alert__icon" }, icon(ic)),
            h("p", { class: "az-alert__title" }, title),
            body ? h("p", { class: "az-alert__body" }, body) : null);
    }
    function card(id, title, extra, body) {
        return h("section", { class: "az-card sm-card", id, "aria-labelledby": id + "-title" },
            h("div", { class: "az-card__header" }, h("h2", { class: "az-card__title", id: id + "-title", text: title }), extra || null),
            h("div", { class: "az-card__body" }, body));
    }
    // A table that becomes blocks on a phone: one cell per column, labelled.
    function table(cols, rows, cls) {
        return h("div", { class: "az-table-wrap" },
            h("table", { class: "az-table az-table--stack" + (cls ? " " + cls : "") },
                h("thead", null, h("tr", null, cols.map((c) => h("th", { scope: "col", text: c.label })))),
                h("tbody", null, rows.map((cells) => h("tr", cells.attrs || null,
                    (cells.cells || cells).map((cell, i) => h("td", { "data-label": cols[i].label, class: cols[i].cls || null },
                        h("span", { class: "sm-v" }, cell))))))));
    }
    function kv(pairs) {
        return h("dl", { class: "sm-kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", { text: k }), h("dd", null, v)]));
    }
    const $ = (id) => document.getElementById(id);

    // --- Time --------------------------------------------------------------
    function fmtDate(iso) {
        const d = new Date(iso || "");
        return isNaN(d) ? "?" : d.toLocaleString(LOCALE, { dateStyle: "medium", timeStyle: "short" });
    }
    function fmtDay(ms) {
        return new Date(ms).toLocaleDateString(LOCALE, { day: "numeric", month: "long" });
    }
    // The start of the journal when it covers clearly less than the 14 days the logins are read
    // for (more than a day missing), else null; as lib/secstatus.py journal_short().
    function journalShort(lg, generated) {
        const start = Date.parse(lg.journal_start || "");
        const now = Date.parse(generated || "");
        if (isNaN(start) || isNaN(now)) return null;
        return start - (now - 14 * 86400000) > 86400000 ? start : null;
    }
    function minutesSince(iso) {
        const ts = Date.parse(iso || "");
        return isNaN(ts) ? null : Math.max(0, (Date.now() - ts) / 60000);
    }
    function ago(iso) {
        const m = minutesSince(iso);
        if (m === null) return "?";
        if (m < 1) return t("ago.now");
        if (m < 60) return t("ago.min", { n: Math.round(m) });
        const hr = Math.round(m / 60);
        return hr < 48 ? t("ago.h", { n: hr }) : t("ago.d", { n: Math.round(hr / 24) });
    }
    function age(iso) {
        const m = Math.round(minutesSince(iso) || 0);
        if (m < 60) return t("age.min", { n: m });
        const hr = Math.round(m / 60);
        return hr < 48 ? t("age.h", { n: hr }) : t("age.d", { n: Math.round(hr / 24) });
    }

    // --- The system ----------------------------------------------------------
    function spawn(argv, superuser) {
        return cockpit.spawn(argv, { superuser, err: superuser === "require" ? "out" : "message",
                                     environ: ["SECURITY_LANG=" + LANG] });
    }
    function isNoAdmin(ex) {
        ex = ex || {};
        return ex.exit_status === 77 || /access-denied|not-authorized|authentication/.test(ex.problem || "");
    }

    let view = null;        // security.py show: {root, state, marks_problem, timer, next, running, hetzner_token}
    let summary = null;     // security.py status, without administrative access
    let admin = null;       // true, false, or null while not known
    let loadError = null;
    let flash = null;       // a message of the last scan until the next good one
    let scanning = false;
    let autoScanned = false;
    let loadedOnce = false;
    let tab = "exposure";

    function state() { return view && view.state; }

    // --- Page messages -----------------------------------------------------
    function renderStatus() {
        const out = [];
        const st = state();
        if (loadError) out.push(alertBox("danger", t("status.loadErrorTitle"), loadError));
        if (flash) out.push(alertBox(flash.kind, t(flash.title), rich(t(flash.body))));
        if (admin === false) out.push(alertBox("info", t("status.noAdminTitle"), rich(t("status.noAdmin"))));
        if (admin && !st && !loadError && !scanning && autoScanned) {
            out.push(alertBox("info", t("status.noStateTitle"), rich(t("status.noState"))));
        }
        if (st) {
            if (st.format > FORMAT) out.push(alertBox("info", t("status.newerTitle"), rich(t("status.newer"))));
            const m = minutesSince(st.generated);
            if (m !== null && m > STALE_MIN) {
                out.push(alertBox("warning", t("status.oldTitle", { age: age(st.generated) }), rich(t("status.old"))));
            }
        }
        if (view && view.marks_problem) {
            const body = view.marks_problem === "untrusted"
                ? tr("status.marksUntrusted", { file: view.marks_file || MARKS_FILE })
                : tr("status.marksLines", { file: view.marks_file || MARKS_FILE, lines: view.marks_problem });
            out.push(alertBox("warning", t("status.marksTitle"), body));
        }
        fill($("sm-status"), out);
    }

    function renderMeta() {
        const el = $("sm-meta");
        const st = state();
        const at = st ? st.generated : summary ? summary.checked_at : null;
        if (!at || (summary && summary.state === "none" && !st)) {
            el.textContent = t("meta.never");
            el.removeAttribute("title");
            return;
        }
        el.textContent = t("meta.checked", { ago: ago(at) });
        el.title = t("meta.tip", { when: fmtDate(at), secs: Math.round(((st && st.took_ms) || 0) / 100) / 10 });
    }

    // --- Tabs --------------------------------------------------------------
    function visibleTabs() {
        const st = state();
        // CrowdSec and fail2ban only when installed.
        return TABS.filter((k) => (k !== "crowdsec" && k !== "fail2ban") || !!(st && st[k] && st[k].installed));
    }
    function renderTabs() {
        const nav = $("sm-tabs");
        const tabs = visibleTabs();
        nav.hidden = admin === false;
        if (tabs.indexOf(tab) < 0) tab = "exposure";
        nav.querySelectorAll("[role=tab]").forEach((b) => {
            const on = b.dataset.tab === tab;
            b.hidden = tabs.indexOf(b.dataset.tab) < 0;
            b.setAttribute("aria-selected", on ? "true" : "false");
            b.tabIndex = on ? 0 : -1;
        });
        TABS.forEach((k) => { $("sm-tab-" + k).hidden = admin === false || k !== tab; });
        $("sm-summary").hidden = admin !== false;
    }
    function selectTab(k, focus) {
        if (TABS.indexOf(k) < 0) return;
        tab = k;
        renderTabs();
        if (focus) {
            const b = document.querySelector('[role=tab][data-tab="' + k + '"]');
            if (b) b.focus();
        }
    }
    function followLocation() {
        const first = ((cockpit.location && cockpit.location.path) || [])[0] || "";
        if (TABS.indexOf(first) >= 0) selectTab(first);
    }

    // --- Links to a port: #/exposure/<port>-<proto> ----------------------------------
    // The status links each finding to its port. Cockpit keeps the page's frame and only
    // changes the location, also while the frame is hidden: the row is marked for as long
    // as the location names it, and brought into view once, when the rows are there and
    // the page is shown (status contract: "An add-on that sets link must follow it").
    const PORT_PLACE = /^([0-9]{1,5})-(tcp|udp|sctp)$/;
    let place = null;           // the id of the row the location names, or null
    let scrollPending = false;  // that row is still to be brought into view

    function onLocation() {
        const path = (cockpit.location && cockpit.location.path) || [];
        if (TABS.indexOf(path[0] || "") < 0) return;     // an unknown place changes nothing
        const m = path[0] === "exposure" ? PORT_PLACE.exec(path[1] || "") : null;
        place = m ? "sm-port-" + m[2] + "-" + Number(m[1]) : null;
        scrollPending = !!place;
        followLocation();
        markPlace();
        goToPlace();
    }
    function markPlace() {
        document.querySelectorAll(".sm-ports-table tr[aria-current]").forEach((r) => r.removeAttribute("aria-current"));
        const row = place ? $(place) : null;
        if (row) row.setAttribute("aria-current", "location");
    }
    function goToPlace() {
        if (!scrollPending || cockpit.hidden || !state()) return;
        scrollPending = false;
        const row = $(place);
        if (!row || row.closest("[hidden]")) return;
        const det = row.querySelector("details");
        if (det) det.open = true;
        if (typeof row.scrollIntoView === "function") row.scrollIntoView({ block: "start" });
    }
    // A tab chosen on the page goes into the location, and the place of a link ends there.
    function chooseTab(k, focus) {
        if (typeof cockpit.location.go === "function") cockpit.location.go([k]);
        place = null;
        scrollPending = false;
        markPlace();
        selectTab(k, focus);
    }

    // --- Summary without administrative access ---------------------------------
    function renderSummary() {
        const box = $("sm-summary");
        if (admin !== false) { fill(box); return; }
        const items = (summary && summary.items) || [];
        const list = h("ul", { class: "sm-plain-list sm-summary-list" }, items.map((i) =>
            h("li", null, label(i.state), " ", h("strong", { text: i.title }), i.value ? " " + i.value : "",
                i.detail ? h("span", { class: "sm-sub", text: i.detail }) : null)));
        fill(box, card("sm-sum", t("sum.title"), summary ? label(summary.state) : null,
            [h("p", { class: "sm-intro", text: summary ? summary.summary : t("status.noState") }), items.length ? list : null,
             h("p", { class: "sm-note", text: t("sum.intro") })]));
    }

    // --- Exposure ----------------------------------------------------------------
    function famBinds(p, fam) {
        return (p.binds || []).filter((b) => (fam === "6" ? /^\[|^\*/.test(b) : !/^\[/.test(b)));
    }
    function reachCell(p, cls) {
        const r4 = p.reach["4"][cls].result;
        const r6 = p.reach["6"][cls].result;
        const word = (r) => t("reach." + (r || "absent"));
        // One word when both families agree, or when one of them has no address in this class.
        if (r4 === r6 || r6 === "absent" || r4 === "absent") {
            const r = r4 === "absent" ? r6 : r4;
            return h("span", { class: "sm-reach sm-reach--" + r, text: word(r) });
        }
        const parts = [];
        if (r4 !== "absent") parts.push(t("reach.fam", { fam: "IPv4", what: word(r4) }));
        if (r6 !== "absent") parts.push(t("reach.fam", { fam: "IPv6", what: word(r6) }));
        return h("span", { class: "sm-reach", text: parts.join(" · ") });
    }
    function serviceCell(p) {
        const s = p.service || {};
        const main = s.containers && s.containers.length ? t("svc.container", { names: s.containers.join(", ") })
            : s.kind === "kernel" ? t("svc.kernel") : (s.processes || []).join(", ") || "?";
        const sub = [];
        if (p.name) sub.push(p.name);
        if ((s.images || []).length) sub.push(s.images.join(", "));
        if (s.kind === "docker" && (s.container_ports || []).length && s.container_ports.join() !== String(p.port)) {
            sub.push(t("svc.toPort", { port: s.container_ports.join(", ") }));
        }
        return [h("span", { text: main }), sub.length ? h("span", { class: "az-cell-sub", text: sub.join(" · ") }) : null];
    }
    function ufwLoaded(st, fam) {
        const u = st.firewall && st.firewall.ufw;
        return !!(u && u.loaded && u.loaded[fam]);
    }
    function where(ref) {
        return t("det.where", { chain: ref.chain, family: ref.family, table: ref.table }) +
            (ref.owner ? " (" + t("det.owner." + ref.owner) + ")" : "");
    }
    // The Hetzner Cloud Firewalls of an answer, by name, else by number (rules missing from the API's answer).
    function hzNames(refs) {
        return (refs || []).map((x) => x.firewall || (x.id != null ? "#" + x.id : "")).filter(Boolean).join(", ");
    }
    // The rules of a Hetzner Cloud Firewall applied to the server are not known: it counts as no protection.
    function hzUnknown(p) {
        return ["4", "6"].some((f) => (p.reach[f].internet.hetzner || {}).result === "unknown");
    }
    function shortReason(p, st) {
        const inet = ["4", "6"].map((f) => p.reach[f].internet);
        const open = inet.find((r) => r.result === "open");
        if (p.why === "outside-only") return t(hzUnknown(p) ? "sub.outsideHz" : "sub.outside");
        if (p.why === "restricted") {
            return t("sub.restricted", { list: [...new Set(inet.flatMap((r) => r.sources || []))].join(", ") });
        }
        if (p.why === "unknown") {
            const reasons = inet.map((r) => r.reason);
            return t(reasons.indexOf("no-addresses") >= 0 ? "sub.noAddresses" : reasons.indexOf("no-rules") >= 0 ? "sub.noRules"
                : reasons.indexOf("no-docker") >= 0 ? "sub.noDocker" : "sub.unknown");
        }
        if (p.why === "hetzner") {
            const hz = inet.map((r) => r.hetzner).find(Boolean);
            const names = hz ? hzNames(hz.refs) : "";
            return t("sub.hetzner", { firewall: t("ov.hetzner") + (names ? " " + names : "") });
        }
        if (open && open.path === "forward") {
            const fam = p.reach["4"].internet === open ? "4" : "6";
            return t(ufwLoaded(st, fam) ? "sub.forwardPastUfw" : "sub.forward");
        }
        if (p.why === "public-danger") return t("sub.danger", { name: p.name || "?" });
        return null;
    }
    function stepText(step) {
        if (step.result === "unknown" && step.rule) return tr("det.unknownRule", { rule: step.rule.text, where: where(step.rule) });
        if (step.rule) return tr("det.rule", { rule: step.rule.text, where: where(step.rule) });
        return tr("det.policy", { policy: step.chain.policy || "accept", where: where(step.chain) });
    }
    // The rule (or policy) that keeps out everyone but the allowed sources of a restricted port.
    function limitText(step) {
        if (step.rule) return tr("det.limitRule", { rule: step.rule.text, where: where(step.rule) });
        return tr("det.limitPolicy", { policy: step.chain.policy || "drop", where: where(step.chain) });
    }
    function classLine(cls, r) {
        let res = t("det.res." + r.result, { list: (r.sources || []).join(", ") });
        const why = [];
        if (r.reason === "local-published") why.push(rich(t("det.localPublished")));
        else if (r.reason === "no-rules") why.push(rich(t("det.noRules")));
        else if (r.reason === "no-addresses") why.push(rich(t("det.noAddresses")));
        else if (r.reason === "no-docker") why.push(rich(t("det.noDocker")));
        if (r.limited_by) why.push(limitText(r.limited_by));
        const steps = r.steps || [];
        const decisive = r.result === "unknown" ? steps.filter((s) => s.result === "unknown") :
            r.result === "closed" ? steps.filter((s) => s.result === "drop") : steps.filter((s) => s.rule || s.policy);
        decisive.slice(0, 2).forEach((s) => why.push(stepText(s)));
        if (r.host_result) res = t("det.res." + r.host_result, { list: "" }) + " → " + res;
        return h("li", null, h("strong", { text: t("det.class." + cls) + ": " }), res,
            why.length ? [": ", why.reduce((acc, x, i) => acc.concat(i ? ["; ", x] : [x]), [])] : null);
    }
    function details(p, st) {
        const blocks = [];
        ["4", "6"].forEach((fam) => {
            const r = p.reach[fam];
            if (CLASSES.every((c) => r[c].result === "absent")) return;
            const lines = [];
            const binds = famBinds(p, fam);
            if (binds.length) lines.push(h("p", null, tr("det.binds", { list: binds.join(", ") })));
            const fwd = CLASSES.map((c) => r[c]).find((x) => x.path === "forward" && x.to);
            if (fwd) {
                lines.push(h("p", null, tr("det.forward", { addr: fwd.to.addr, port: fwd.to.port, rule: fwd.to.rule.text,
                                                            where: where(fwd.to.rule) })));
                if (ufwLoaded(st, fam)) lines.push(h("p", null, rich(t("det.ufwForward"))));
                if (!((st.firewall || {}).docker_user || {})[fam]) lines.push(h("p", null, rich(t("det.dockerUserNone"))));
            }
            if (CLASSES.some((c) => r[c].proxy)) lines.push(h("p", null, rich(t("det.proxy"))));
            lines.push(h("ul", { class: "sm-plain-list" }, CLASSES.filter((c) => r[c].result !== "absent").map((c) => classLine(c, r[c]))));
            const hz = r.internet.hetzner;
            if (hz && hz.result !== "none") {
                const names = hzNames(hz.refs) || "?";
                lines.push(h("p", null, tr("det.hz." + hz.result, { names, list: (hz.sources || []).join(", ") })));
            }
            blocks.push(h("div", { class: "sm-detail-fam" }, h("p", { class: "sm-sub-title", text: t("det.fam", { fam }) }), lines));
        });
        if (p.why === "outside-only") blocks.push(h("p", null, rich(t(hzUnknown(p) ? "det.outsideHz" : "det.outside"))));
        const todo = todoList(p, st);
        if (todo.length) blocks.push(h("div", { class: "sm-todo" }, h("p", { class: "sm-sub-title", text: t("todo.title") }),
                                       h("ul", { class: "sm-plain-list" }, todo.map((x) => h("li", null, x)))));
        return h("details", { class: "sm-details" }, h("summary", null, icon("angle-right"), h("span", { text: t("btn.details") })), blocks);
    }
    // What one can do about a port the internet reaches: shown as text, never run.
    function todoList(p, st) {
        if (p.expected !== undefined || ["warning", "danger"].indexOf(p.state) < 0) return [];
        const out = [];
        const fams = ["4", "6"].filter((f) => ["open", "restricted"].indexOf(p.reach[f].internet.result) >= 0);
        const fwd = fams.map((f) => p.reach[f].internet).find((r) => r.path === "forward");
        if (fwd) {
            out.push(tr("todo.bind", { port: p.port, cport: (fwd.to && fwd.to.port) || p.port }));
            const vpn = vpnNet(st);
            const bridge = ((st.firewall || {}).docker || {}).backend === "iptables" ? bridgeOf(st, fwd) : null;
            if (vpn && bridge) {
                out.push(tr("todo.dockerUser", { cmd: "iptables -I DOCKER-USER -o " + bridge + " -m conntrack --ctstate NEW ! -s " +
                                                       vpn + " -j DROP" }));
            }
        } else if (fams.some((f) => ufwLoaded(st, f))) {
            out.push(tr("todo.ufw", { port: p.port, proto: p.proto }));
        } else {
            out.push(rich(t("todo.nofilter")));
        }
        out.push(rich(t("todo.expected")));
        return out;
    }
    function vpnNet(st) {
        const ifs = ((st.network || {}).interfaces || []).filter((i) => i.kind === "vpn");
        const a = ifs.flatMap((i) => i.addrs).find((x) => x.family === 4 && x.prefix < 32);
        if (!a) return null;
        const parts = a.addr.split(".").map(Number);
        const mask = a.prefix === 0 ? 0 : (~0 << (32 - a.prefix)) >>> 0;
        const n = (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0) & mask;
        return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".") + "/" + a.prefix;
    }
    function bridgeOf(st, r) {
        const step = (r.steps || []).find((s) => s.rule && /-o (\S+)/.test(s.rule.text));
        const m = step ? step.rule.text.match(/-o (\S+)/) : null;
        return m && /^[A-Za-z0-9_.-]{1,15}$/.test(m[1]) ? m[1] : null;
    }
    function assessCell(p, st) {
        const marked = p.expected !== undefined;
        const word = marked ? t("why.expected") : t("why." + p.why);
        const sub = marked ? (p.expected ? t("why.note", { note: p.expected }) : null) : shortReason(p, st);
        return [label(p.state, word), sub ? h("span", { class: "az-cell-sub", text: sub }) : null, details(p, st)];
    }
    // A mark is offered where the internet reaches a port and the assessment asks for a look:
    // a warning, a danger, or a port that could not be assessed.
    function canMark(p) {
        if (p.expected !== undefined) return true;
        if (["warning", "danger", "none"].indexOf(p.state) < 0) return false;
        return ["4", "6"].some((f) => ["open", "restricted", "unknown"].indexOf(p.reach[f].internet.result) >= 0);
    }
    function portActions(p) {
        if (!admin || !canMark(p)) return null;
        const key = p.port + "/" + p.proto;
        return p.expected !== undefined
            ? btn("az-btn--plain az-btn--sm", "times", t("btn.unexpect"), { "data-unexpect-port": key })
            : btn("az-btn--secondary az-btn--sm", "check", t("btn.expect"), { "data-expect-port": key });
    }

    function filterText(st, fam) {
        // public: true, false, or null when the addresses could not be read
        const pub = ((st.network || {}).public || {})[fam];
        const filter = ((st.firewall || {}).input_filter || {})[fam] || "unknown";
        return t(pub === false && filter === "unknown" ? "ov.filter.noaddr" : "ov.filter." + filter);
    }
    function ufwText(u) {
        if (!u || !u.installed) return t("ov.ufw.missing");
        if (!u.enabled) return t("ov.ufw.off");
        if (!(u.loaded && (u.loaded["4"] || u.loaded["6"]))) return t("ov.ufw.onNoRules");
        return t("ov.ufw.on", { policy: u.default_input || "?" }) + " · " + t("ov.ufw.rules", { n: u.rules_total || 0 });
    }
    // Docker's socket is there, but Docker could not be asked: the ports it publishes are not known.
    function dockerUnread(st) {
        return ["error", "needs-root"].indexOf((((st.sources || {}).docker) || {}).state) >= 0;
    }
    function dockerText(st) {
        const d = st.firewall && st.firewall.docker;
        if (!d) return t(dockerUnread(st) ? "ov.docker.unread" : "ov.docker.missing");
        const line = t(d.backend_known ? "ov.docker.line" : "ov.docker.assumed", { version: d.version || "?", backend: d.backend });
        const du = st.firewall.docker_user || {};
        return [line, h("span", { class: "sm-sub", text: t("ov.docker.user", { n4: du["4"] || 0, n6: du["6"] || 0 }) })];
    }
    function hetznerText(hz) {
        if (!hz || !hz.configured) return rich(t("ov.hetzner.none"));
        const names = (hz.firewalls || []).map((f) => f.name || "#" + f.id).join(", ");
        // Applied, but missing from the API's answer: its rules are not known.
        const unknown = (hz.firewalls || []).filter((f) => (f.status || "applied") === "applied" && !Array.isArray(f.rules))
            .map((f) => f.name || "#" + f.id).join(", ");
        const note = unknown ? h("span", { class: "sm-sub", text: t("ov.hetzner.rulesUnknown", { names: unknown }) }) : null;
        if (hz.state === "ok") {
            return names ? [t("ov.hetzner.ok", { names, when: fmtDate(hz.ok_at) }), note]
                : t("ov.hetzner.noFirewall", { server: (hz.server && hz.server.name) || "?" });
        }
        if (hz.state === "stale") return [t("ov.hetzner.stale", { when: fmtDate(hz.ok_at), error: hz.error || "?" }), note];
        if (hz.state === "error") return t("ov.hetzner.error", { error: hz.error || "?" });
        return t("ov.hetzner." + ({ pending: "pending", "not-matched": "notMatched", unreadable: "unreadable" }[hz.state] || "pending"));
    }
    function timerLine() {
        const tm = view && view.timer;
        let text = t("ov.timer.missing");
        let b = null;
        if (tm === "active") {
            text = view.next ? t("ov.timer.on", { when: fmtDate(view.next) }) : t("ov.timer.onNoNext");
            if (admin) b = btn("az-btn--plain az-btn--sm", "stop", t("btn.switchOff"), { id: "sm-timer-off" });
        } else if (tm === "inactive") {
            text = t("ov.timer.off");
            if (admin) b = btn("az-btn--secondary az-btn--sm", "play", t("btn.setup"), { id: "sm-timer-setup" });
        }
        return h("span", { class: "sm-line" }, h("span", { text }), b);
    }

    function uncheckedCard(id, items, sourcesOf) {
        const st = state();
        const src = (st && st.sources) || {};
        const bad = sourcesOf.filter((k) => src[k] && ["missing", "skipped", "ok"].indexOf(src[k].state) < 0 &&
                                         !(src[k].state === "partial" && !src[k].missing));
        const list = bad.map((k) => h("li", null, tr("unchecked.source", { what: t("src." + k),
            reason: t("reason." + src[k].state, { msg: src[k].error || "" }) })));
        return card(id, t("unchecked.title"), null, [h("p", { class: "sm-intro", text: t("unchecked.intro") }),
            h("ul", { class: "sm-plain-list" }, list, items.map((x) => h("li", null, x)))]);
    }

    function renderExposure() {
        const box = $("sm-tab-exposure");
        const st = state();
        if (!st) { fill(box); return; }
        const ports = (st.ports || []).slice().sort((a, b) => (ORDER[b.state] - ORDER[a.state]) || (a.port - b.port) ||
                                                               (a.proto < b.proto ? -1 : 1));
        const reached = (p, result) => ["4", "6"].some((f) => p.reach[f].internet.result === result);
        const pub = ports.filter((p) => reached(p, "open") || reached(p, "restricted"));
        const open = pub.filter((p) => reached(p, "open"));
        const limited = pub.length - open.length;
        const attention = pub.filter((p) => ORDER[p.state] >= ORDER.warning);
        const unknown = ports.filter((p) => p.state === "none");
        // What the exposure rests on: without it nothing here may read as "nothing reachable".
        const read = (k, partial) => { const s = (((st.sources || {})[k]) || {}).state; return s === "ok" || (partial && s === "partial"); };
        const addrsRead = read("ip");
        const socketsRead = read("ss", true);
        const rulesRead = read("rules");
        const dockerRead = !dockerUnread(st);
        const intro = [];
        if (!addrsRead) intro.push(h("p", { text: t("ov.noAddresses") }));
        if (!socketsRead) intro.push(h("p", { text: t("ov.noSockets") }));
        if (!rulesRead) intro.push(h("p", { text: t("ov.noRules") }));
        if (!dockerRead) intro.push(h("p", { text: t("ov.noDocker") }));
        if (addrsRead && !Object.values((st.network || {}).public || {}).some(Boolean)) intro.push(h("p", { text: t("ov.noPublic") }));
        if (open.length) intro.push(h("p", { text: t("ov.public", { n: open.length }) }));
        if (limited) intro.push(h("p", { text: t("ov.limited", { n: limited }) }));
        if (!pub.length && addrsRead && socketsRead && rulesRead && dockerRead) intro.push(h("p", { text: t("ov.publicNone") }));
        if (attention.length) {
            intro.push(h("p", { text: t("ov.attention", { n: attention.length }) },
                h("span", { class: "sm-chips" }, attention.map((p) => label(p.state, p.port + "/" + p.proto + (p.name ? " " + p.name : ""))))));
        }
        if (unknown.length) intro.push(h("p", { text: t("ov.unknown", { n: unknown.length }) }));
        const fw = st.firewall || {};
        const overview = card("sm-ov", t("ov.title"), null, [h("div", { class: "sm-intro-block" }, intro), kv([
            [t("ov.filter4"), filterText(st, "4")],
            [t("ov.filter6"), filterText(st, "6")],
            [t("ov.ufw"), ufwText(fw.ufw)],
            [t("ov.docker"), dockerText(st)],
            [t("ov.hetzner"), hetznerText(fw.hetzner)],
            [t("ov.timer"), timerLine()],
        ]), fw.legacy_rules ? h("p", { class: "sm-note", text: t("ov.legacy") }) : null]);
        const cols = [{ label: t("col.port") }, { label: t("col.service") }, { label: t("col.internet") }, { label: t("col.vpn") },
                      { label: t("col.private") }, { label: t("col.local") }, { label: t("col.assessment"), cls: "sm-assess" },
                      { label: t("col.actions"), cls: "az-cell-actions" }];
        const rows = ports.map((p) => ({ attrs: { id: "sm-port-" + p.proto + "-" + p.port, "data-state": p.state }, cells: [
            h("span", { class: "az-mono", text: p.port + "/" + p.proto }), serviceCell(p),
            reachCell(p, "internet"), reachCell(p, "vpn"), reachCell(p, "private"), reachCell(p, "local"),
            assessCell(p, st), portActions(p)] }));
        const portsCard = card("sm-ports", t("ports.title"), null, [h("p", { class: "sm-intro", text: t("ports.intro") }),
            rows.length ? table(cols, rows, "sm-ports-table") : h("p", { text: t(socketsRead ? "ports.empty" : "ports.noSockets") })]);
        const un = uncheckedCard("sm-unchecked-exposure", [rich(t("unchecked.exposure.rules")), rich(t("unchecked.exposure.outside")),
            rich(t("unchecked.exposure.out")), rich(t("unchecked.exposure.weak"))], ["ip", "ss", "rules", "docker", "ufw", "hetzner"]);
        fill(box, overview, portsCard, un);
    }

    // --- SSH -----------------------------------------------------------------
    function renderSsh() {
        const box = $("sm-tab-ssh");
        const st = state();
        if (!st) { fill(box); return; }
        const ssh = st.ssh || {};
        const sshd = ssh.sshd || {};
        let cfg;
        if (sshd.state === "ok") {
            cfg = table([{ label: t("col.setting") }, { label: t("col.value") }, { label: t("col.assessment") }, { label: t("col.meaning") }],
                (ssh.findings || []).map((f) => [code(f.key), h("span", { class: "az-mono", text: f.value || "–" }), label(f.state),
                                                h("span", { text: t("sshd." + f.code) })]));
        } else if (sshd.state === "error" && sshd.reason === "privsep-dir-missing") {
            cfg = alertBox("warning", rich(t("ssh.privsepTitle")), rich(t("ssh.privsep")));
        } else if (sshd.state === "error") {
            cfg = alertBox("warning", rich(t("ssh.errorTitle")), sshd.error || "");
        } else if (sshd.state === "missing") {
            cfg = h("p", null, rich(t("ssh.missing")));
        } else {
            cfg = h("p", { text: t("reason.needs-root") });
        }
        const config = card("sm-sshd", t("ssh.title"), label(sshd.state === "ok" ? worst((ssh.findings || []).map((f) => f.state)) : "none"),
            [h("p", { class: "sm-intro" }, rich(t("ssh.intro"))), cfg]);
        const files = ssh.keys || [];
        const keyCols = [{ label: t("col.type") }, { label: t("col.bits") }, { label: t("col.fingerprint") }, { label: t("col.comment") },
                         { label: t("col.options") }, { label: t("col.findings") }];
        const fileNotes = (f) => {
            const items = (f.problems || []).map((x) => h("li", null, label("warning", t("file." + x))));
            if ((f.account || {}).finding === "locked-with-keys") {
                items.push(h("li", { class: "sm-account" }, label("warning", t("account.locked")), " ",
                    tr("account.locked-with-keys", { user: f.user })));
            }
            return items.length ? h("ul", { class: "sm-plain-list" }, items) : null;
        };
        const fileBlocks = files.map((f) => h("div", { class: "sm-keyfile", "data-state": f.state },
            h("p", { class: "sm-sub-title" }, tr("keys.file", { user: f.user, file: f.file, mode: f.mode || "?" }), " ", label(f.state)),
            fileNotes(f),
            f.keys.length ? table(keyCols, f.keys.map((k) => [
                h("span", { class: "az-mono", text: k.type || "?" }), k.bits ? t("keys.bits", { n: k.bits }) : "–",
                k.fingerprint ? h("span", { class: "az-mono", text: k.fingerprint }) : "–", k.comment || "–",
                k.options && k.options.length ? h("span", { class: "az-mono", text: k.options.join(",") }) : "–",
                k.findings.length ? h("span", { class: "sm-chips" }, k.findings.map((x) => label(x.state, t("key." + x.code)))) : label("ok", t("key.ok"))]))
                : h("p", { class: "sm-note", text: t("keys.empty") })));
        const keys = card("sm-keys", t("keys.title"), null, [h("p", { class: "sm-intro", text: t("keys.intro") }),
            files.length ? fileBlocks : h("p", { text: t("keys.none") })]);
        const extra = [];
        if ((sshd.match || []).length) extra.push(tr("unchecked.ssh.match", { files: sshd.match.join(", ") }));
        extra.push(rich(t("unchecked.ssh.more")));
        fill(box, config, keys, uncheckedCard("sm-unchecked-ssh", extra, ["sshd", "keys"]));
    }
    function worst(states) {
        return states.reduce((a, s) => (ORDER[s] > ORDER[a] ? s : a), "ok");
    }

    // --- Logins --------------------------------------------------------------
    function classLabel(cls) {
        if (!cls) return h("span", { class: "az-cell-sub", text: t("src.unknown") });
        const state = ["vpn", "private", "local", "link"].indexOf(cls) >= 0 ? "ok" : cls === "internet" || cls === "cgnat" ? "warning" : "none";
        return label(state, t("src.class." + cls));
    }
    function renderLogins() {
        const box = $("sm-tab-logins");
        const st = state();
        if (!st) { fill(box); return; }
        const lg = st.logins || {};
        if (lg.state !== "ok") {
            fill(box, card("sm-logins", t("logins.title"), label("none"), h("p", { text: t("logins.unchecked") })),
                 uncheckedCard("sm-unchecked-logins", [rich(t("unchecked.logins.age"))], ["journal"]));
            return;
        }
        const ok = lg.success || [];
        const start = journalShort(lg, st.generated);
        const okCard = card("sm-logins", t("logins.title"), label(lg.outside ? "warning" : "ok"), [
            start ? h("p", { class: "sm-note", id: "sm-journal-start", text: t("logins.since", { date: fmtDay(start) }) }) : null,
            h("p", { class: "sm-intro", text: ok.length ? t("logins.intro", { n: lg.success_total }) : t("logins.none") }),
            ok.length ? table([{ label: t("col.time") }, { label: t("col.service") }, { label: t("col.user") }, { label: t("col.source") },
                               { label: t("col.method") }],
                ok.map((s) => ({ attrs: { "data-class": s.class || "" }, cells: [fmtDate(s.time), t("svc." + s.service), s.user,
                    s.source ? [h("span", { class: "az-mono", text: s.source + " " }), classLabel(s.class)] : classLabel(null), s.method] }))) : null,
            lg.success_total > ok.length ? h("p", { class: "sm-note", text: t("logins.more", { n: lg.success_total - ok.length }) }) : null]);
        const failed = lg.failed || [];
        const failCard = card("sm-failed", t("failed.title"), null, [
            h("p", { class: "sm-intro", text: failed.length ? t("failed.intro", { n: lg.failed_total, m: lg.failed_sources }) : t("failed.none") }),
            failed.length ? table([{ label: t("col.source") }, { label: t("col.attempts") }, { label: t("col.accounts") }, { label: t("col.last") },
                                   { label: t("col.service") }],
                failed.map((f) => [[h("span", { class: "az-mono", text: f.source + " " }), classLabel(f.class)], String(f.count), String(f.users),
                                   fmtDate(f.last), f.services.map((s) => t("svc." + s)).join(", ")])) : null]);
        const sudo = lg.sudo || [];
        const sudoCard = card("sm-sudo", t("sudo.title"), null, sudo.length
            ? table([{ label: t("col.user") }, { label: t("col.uses") }, { label: t("col.failures") }, { label: t("col.last") }],
                sudo.map((s) => [s.user, String(s.uses), String(s.failures), s.last ? fmtDate(s.last) : "–"]))
            : h("p", { text: t("sudo.none") }));
        fill(box, okCard, failCard, sudoCard, uncheckedCard("sm-unchecked-logins", [rich(t("unchecked.logins.age")),
            rich(t("unchecked.logins.apps")), rich(t("unchecked.logins.cockpit"))], ["journal"]));
    }

    // --- Containers ------------------------------------------------------------
    function findingItem(c, f) {
        const text = t("ck." + f.kind, { detail: f.detail || "" });
        const marked = f.expected !== undefined;
        const kids = [label(f.state, null), " ", rich(text)];
        if (marked) kids.push(h("span", { class: "sm-sub", text: f.expected ? t("ck.expected", { note: f.expected }) : t("ck.expectedNoNote") }));
        if (admin && (marked || ORDER[f.state] >= ORDER.warning)) {
            kids.push(marked
                ? btn("az-btn--plain az-btn--sm", "times", t("btn.unexpect"), { "data-unexpect-container": c.name, "data-kind": f.kind })
                : btn("az-btn--link az-btn--sm", "check", t("btn.expect"), { "data-expect-container": c.name, "data-kind": f.kind }));
        }
        return h("li", { "data-kind": f.kind, "data-state": f.state }, kids);
    }
    function renderContainers() {
        const box = $("sm-tab-containers");
        const st = state();
        if (!st) { fill(box); return; }
        const cs = st.containers || {};
        const items = cs.items || [];
        let body;
        if (cs.state !== "ok") body = h("p", { text: (st.sources.docker || {}).state === "missing" ? t("containers.missing") : t("reason.needs-root") });
        else if (!items.length) body = h("p", { text: t("containers.none") });
        else {
            const sorted = items.slice().sort((a, b) => (ORDER[b.state || worst(b.findings.map((f) => f.state))] -
                                                         ORDER[a.state || worst(a.findings.map((f) => f.state))]) || (a.name < b.name ? -1 : 1));
            body = table([{ label: t("col.container") }, { label: t("col.image") }, { label: t("col.findings"), cls: "sm-findings" }],
                sorted.map((c) => ({ attrs: { id: "sm-container-" + c.name }, cells: [h("strong", { text: c.name }), h("span", { class: "az-mono", text: c.image }),
                    c.findings.length ? h("ul", { class: "sm-plain-list sm-findings-list" }, c.findings.map((f) => findingItem(c, f)))
                        : label("ok", t("ck.none"))] })));
        }
        fill(box, card("sm-containers", t("containers.title"), null, [h("p", { class: "sm-intro", text: t("containers.intro") }), body]),
             uncheckedCard("sm-unchecked-containers", [rich(t("unchecked.containers.images")), rich(t("unchecked.containers.more"))], ["docker"]));
    }

    // --- CrowdSec ----------------------------------------------------------------
    function renderCrowdsec() {
        const box = $("sm-tab-crowdsec");
        const st = state();
        const cs = st && st.crowdsec;
        if (!cs || !cs.installed) { fill(box); return; }
        const findings = cs.findings || [];
        const top = card("sm-crowdsec", t("cs.title"), label(cs.state), [h("p", { class: "sm-intro", text: t("cs.intro") }), kv([
            [t("cs.service"), cs.active || "?"],
            [t("cs.version"), cs.version || "?"],
            [t("cs.sharing"), t(cs.sharing ? "cs.sharing.on" : "cs.sharing.off")],
        ]), findings.map((f) => alertBox(f.state === "danger" ? "danger" : "warning", t("label." + f.state),
            tr("cs." + f.code, { value: f.value || "" }))),
            Object.keys(cs.errors || {}).length ? h("p", { class: "sm-note", text: t("cs.errors", { list: Object.keys(cs.errors).join(", ") }) }) : null]);
        const b = cs.bouncers || [];
        const bouncers = card("sm-bouncers", t("cs.bouncers"), null, b.length
            ? table([{ label: t("col.name") }, { label: t("col.type") }, { label: t("col.version") }, { label: t("col.lastPull") }],
                b.map((x) => [x.name, x.type, h("span", { class: "az-mono", text: x.version }), x.last_pull ? fmtDate(x.last_pull) : "–"]))
            : h("p", { text: t("cs.bouncers.none") }));
        const d = cs.decisions || [];
        const decisions = card("sm-decisions", t("cs.decisions"), null, [
            h("p", { class: "sm-intro", text: d.length ? t("cs.decisions.intro", { n: cs.decisions_total }) : t("cs.decisions.none") }),
            d.length ? table([{ label: t("col.value2") }, { label: t("col.scenario") }, { label: t("col.duration") }, { label: t("col.origin") },
                              { label: t("col.country") }],
                d.map((x) => [h("span", { class: "az-mono", text: x.value }), x.scenario, x.duration, x.origin, x.country || "–"])) : null]);
        const sc = cs.scenarios || [];
        const scenarios = card("sm-scenarios", t("cs.scenarios"), null, sc.length
            ? table([{ label: t("col.scenario") }, { label: t("col.count") }], sc.map((x) => [h("span", { class: "az-mono", text: x.scenario }), String(x.count)]))
            : h("p", { text: t("cs.scenarios.none") }));
        fill(box, top, bouncers, decisions, scenarios, uncheckedCard("sm-unchecked-crowdsec", [rich(t("unchecked.crowdsec.more"))], ["crowdsec"]));
    }

    // --- fail2ban ----------------------------------------------------------------
    // Shown only: the page installs nothing, sets up no jail and lifts no ban.
    function f2bText(jail, f) {
        return tr("f2b." + f.code, { jail: jail || "", value: f.value == null ? "" : f.value, days: f.days == null ? "" : f.days,
                                     date: f.code === "no-match" ? fmtDate(f.value) : "", chains: (f.chains || []).join(", ") });
    }
    function f2bLog(l) {
        const note = l.exists === false ? t("f2b.log.missing") : l.mtime ? t("f2b.log.changed", { ago: ago(l.mtime) }) : "";
        return h("div", null, h("span", { class: "az-mono", text: l.path }), note ? h("span", { class: "sm-sub", text: note }) : null);
    }
    function f2bAction(a) {
        const where = (a.where || []).join(", ") || "?";
        const ports = a.allports ? t("f2b.allports") : (a.port || "?");
        return h("div", null, h("span", { class: "az-mono", text: a.name + " " }), t("f2b.in", { where }),
            h("span", { class: "sm-sub", text: t("f2b.ports", { ports, protocols: (a.protocols || []).join(", ") }) +
                (a.observed ? " · " + t("f2b.observed") : "") }));
    }
    // A jail's findings, why its own state could not be read, or no finding (OK only when checked).
    function f2bJailFindings(j) {
        const items = (j.findings || []).map((f) => h("li", { "data-code": f.code, "data-state": f.state },
            label(f.state, null), " ", f2bText(j.name, f)));
        if (j.error) {
            items.push(h("li", { "data-code": "error", "data-state": "none" }, label("none", null), " ",
                tr("f2b.jail.error", { jail: j.name, error: j.error })));
        }
        if (j.skipped) {
            items.push(h("li", { "data-code": "skipped", "data-state": "none" }, label("none", null), " ", t("f2b.jail.skipped")));
        }
        if (items.length) return h("ul", { class: "sm-plain-list sm-findings-list" }, items);
        return j.state === "none" ? label("none", t("f2b.jail.notChecked")) : label("ok", t("ck.none"));
    }
    function renderFail2ban() {
        const box = $("sm-tab-fail2ban");
        const st = state();
        const fb = st && st.fail2ban;
        if (!fb || !fb.installed) { fill(box); return; }
        const num = (v) => (v == null ? "–" : String(v));
        // A count as a number, so that t() takes the singular for 1 (the dump may give "1").
        const count = (v) => (v == null ? "–" : /^\d+$/.test(String(v)) ? Number(v) : String(v));
        const errors = fb.errors || {};
        // The essential parts that could not be read (the state is then "not checked", never OK),
        // and apart from them fail2ban's database, which only the history needs.
        const failedJails = (fb.jails || []).filter((j) => j.error).map((j) => j.name);
        const skippedJails = (fb.jails || []).filter((j) => j.skipped).map((j) => j.name);
        const unread = (fb.incomplete || []).map((k) => (k === "jails"
            ? tr("f2b.part.jails", { n: failedJails.length, names: failedJails.join(", ") })
            : k === "skipped" ? tr("f2b.part.skipped", { n: skippedJails.length, names: skippedJails.join(", ") })
                : tr("f2b.part." + k, { error: errors[k] || "?" })));
        const unreadBox = unread.length ? alertBox("warning", t("f2b.incompleteTitle"),
            [unread.reduce((acc, x, i) => acc.concat(i ? [" ", x] : [x]), []), " ", t("f2b.incompleteNote")]) : null;
        const service = fb.running ? t("f2b.running", { since: fb.since ? fmtDate(fb.since) : "?" })
            : errors.ping ? tr("f2b.noAnswer", { state: fb.active || "?" }) : t("f2b.stopped", { state: fb.active || "?" });
        const top = card("sm-fail2ban", t("f2b.title"), label(fb.state), [h("p", { class: "sm-intro", text: t("f2b.intro") }), kv([
            [t("f2b.service"), service],
            [t("f2b.version"), fb.version || "?"],
            [t("f2b.bansNow"), num(fb.bans_total)],
            fb.history_total == null ? null : [t("f2b.history", { days: fb.history_days }), String(fb.history_total)],
            [t("f2b.purge"), h("span", { class: "az-mono", text: fb.dbpurgeage || "?" })],
        ]), unreadBox, (fb.findings || []).map((f) => alertBox(f.state === "danger" ? "danger" : f.state === "info" ? "info" : "warning",
            t("label." + f.state), f2bText(null, f))),
            errors.db ? h("p", { class: "sm-note", id: "sm-f2b-history-unread" }, tr("f2b.historyUnread", { error: errors.db })) : null]);
        const jails = (fb.jails || []).slice().sort((a, b) => (ORDER[b.state] - ORDER[a.state]) || (a.name < b.name ? -1 : 1));
        const jailCard = card("sm-f2b-jails", t("f2b.jailsTitle"), null, [h("p", { class: "sm-intro", text: t("f2b.jailsIntro") }), jails.length
            ? table([{ label: t("col.jail") }, { label: t("col.reads") }, { label: t("col.bansIn") }, { label: t("col.counts") },
                     { label: t("col.findings"), cls: "sm-findings" }],
                jails.map((j) => ({ attrs: { id: "sm-f2b-jail-" + j.name.replace(/[^A-Za-z0-9_-]/g, "_"), "data-state": j.state }, cells: [
                    [h("strong", { text: j.name }), j.running === false ? h("span", { class: "sm-sub", text: t("f2b.jail.notRunning") })
                        : j.running == null ? h("span", { class: "sm-sub", text: t("f2b.jail.unknown") }) : null],
                    String(j.backend || "").indexOf("systemd") === 0
                        ? h("div", null, t("f2b.journal"), h("span", { class: "sm-sub az-mono", text: j.journal || "" }))
                        : (j.logs || []).map(f2bLog),
                    (j.actions || []).length ? j.actions.map(f2bAction) : "?",
                    [t("f2b.counts", { hits: t("f2b.counts.hits", { n: count(j.failed_total) }), now: num(j.banned_now),
                                       bans: t("f2b.counts.bans", { n: count(j.banned_total) }) }),
                     h("span", { class: "sm-sub", text: t("f2b.rules", { n: count(j.maxretry), findtime: num(j.findtime), bantime: num(j.bantime) }) })],
                    f2bJailFindings(j)] })))
            : h("p", { text: t("f2b.jails.none") })]);
        const bans = fb.bans || [];
        const banCard = card("sm-f2b-bans", t("f2b.bansTitle"), null, bans.length
            ? table([{ label: t("col.source") }, { label: t("col.jail") }, { label: t("col.since") }, { label: t("col.until") }],
                bans.map((b) => [[h("span", { class: "az-mono", text: b.ip + " " }), classLabel(b.class)], b.jail,
                                 b.since ? fmtDate(b.since) : "–", b.until ? fmtDate(b.until) : (b.since ? t("f2b.permanent") : "–")]))
            : h("p", { text: t(fb.bans_total == null ? "f2b.bans.unknown" : "f2b.bans.none") }));
        fill(box, top, jailCard, banCard, uncheckedCard("sm-unchecked-fail2ban", [rich(t("unchecked.f2b.regex")),
            rich(t("unchecked.f2b.actions"))], ["fail2ban"]));
    }

    function render() {
        renderMeta();
        renderStatus();
        renderTabs();
        renderSummary();
        renderExposure();
        renderSsh();
        renderLogins();
        renderContainers();
        renderCrowdsec();
        renderFail2ban();
        markPlace();
        $("sm-loading").hidden = !((scanning && !state()) || (!loadedOnce));
    }

    // --- Signature -----------------------------------------------------------
    function renderSignature() {
        $("sm-sig-version").textContent = "Security Monitor " + VERSION;
        Promise.resolve().then(() => cockpit.file("/etc/hostname").read())
            .then((text) => {
                const host = String(text || "").trim().split(/\s+/)[0];
                $("sm-sig-host").textContent = host;
                $("sm-sig-host").hidden = !host;
            })
            .catch(() => { /* no host name: the signature shows the product only */ });
    }

    // --- Load and refresh ----------------------------------------------------
    function load() {
        return spawn([HELPER, "show"], "try").then((out) => {
            view = JSON.parse(out);
            admin = true;
            summary = null;
            loadError = null;
        }).catch((ex) => {
            if (!isNoAdmin(ex)) {
                loadError = String((ex && (ex.message || ex.problem)) || ex);
                return;
            }
            admin = false;
            view = null;
            return spawn([HELPER, "status", "--lang", LANG], "try").then((out) => {
                summary = JSON.parse(out);
                loadError = null;
            }).catch((e) => { summary = null; loadError = String((e && (e.message || e.problem)) || e); });
        });
    }

    function setBusy(on) {
        const b = $("sm-refresh");
        b.disabled = on;
        b.classList.toggle("is-busy", on);
        b.setAttribute("aria-busy", on ? "true" : "false");
        b.querySelector(".sm-btn-label").textContent = t(on ? (scanning ? "btn.checking" : "btn.loading") : "btn.refresh");
        document.querySelectorAll("[role=tabpanel]").forEach((p) => p.classList.toggle("is-busy", on && !!state()));
    }

    let loading = false;
    let pending = false;
    function safeLoad() {
        if (loading) { pending = true; return Promise.resolve(); }
        loading = true;
        setBusy(true);
        return Promise.resolve().then(load).catch((err) => {
            loadError = String((err && err.message) || err);
        }).finally(() => {
            loading = false;
            loadedOnce = true;
            if (pending) { pending = false; return safeLoad(); }
            setBusy(scanning);
            render();
            followLocation();
            goToPlace();
            // A fresh install has no state yet: with administrative access, check once.
            if (admin && view && !view.state && !loadError && !autoScanned) {
                autoScanned = true;
                scan();
            }
        });
    }

    // "Refresh": with administrative access a new check through the service,
    // otherwise only the summary again.
    function scan() {
        if (scanning) return;
        if (!admin) { flash = null; safeLoad(); return; }
        scanning = true;
        setBusy(true);
        render();
        spawn([HELPER, "scan"], "require").then(() => {
            flash = null;
        }).catch((ex) => {
            if (isNoAdmin(ex)) flash = { kind: "info", title: "status.noAdminTitle", body: "status.noAdmin" };
            else if (ex && ex.exit_status === 75) flash = { kind: "info", title: "status.busyTitle", body: "status.busy" };
            else flash = { kind: "danger", title: "status.scanFailedTitle", body: "status.scanFailed" };
        }).finally(() => {
            scanning = false;
            safeLoad();
        });
    }

    // Reload when status.json really changed (a new tag), not when the page's own read reports it again.
    function reloadOnChange(file) {
        let seen = false;
        let lastTag = null;
        file.watch((content, tag) => {
            if (seen && tag === lastTag) return;
            const first = !seen;
            seen = true;
            lastTag = tag;
            if (!first && !scanning && !dlg.running) safeLoad();
        });
    }

    // --- Dialog: the timer and the marks -------------------------------------------
    const dlg = {
        running: false,
        argv: null,
        withNote: false,
        open(title, desc, labelText, argv, withNote) {
            this.argv = argv;
            this.withNote = !!withNote;
            $("sm-dialog-title").textContent = title;
            fill($("sm-dialog-desc"), rich(desc));
            const note = $("sm-dialog-note-field");
            note.hidden = !withNote;
            $("sm-dialog-input").value = "";
            const log = $("sm-dialog-log");
            log.textContent = "";
            log.hidden = true;
            this.result("", null);
            const b = $("sm-dialog-confirm");
            b.hidden = false;
            b.disabled = false;
            b.classList.remove("is-busy");
            b.querySelector(".sm-btn-label").textContent = labelText;
            const cancel = $("sm-dialog-cancel");
            cancel.textContent = t("dlg.cancel");
            cancel.disabled = false;
            const el = $("sm-dialog");
            if (typeof el.showModal === "function") el.showModal(); else el.setAttribute("open", "");
            if (withNote) $("sm-dialog-input").focus();
        },
        result(text, ok) {
            const res = $("sm-dialog-result");
            fill(res, text ? [ok === true ? icon("check-circle") : ok === false ? icon("exclamation-circle") : null, text] : null);
            res.className = "sm-dialog-result" + (ok === true ? " is-ok" : ok === false ? " is-error" : "");
        },
        close() {
            if (this.running) return;
            const el = $("sm-dialog");
            if (typeof el.close === "function") el.close(); else el.removeAttribute("open");
        },
        run() {
            if (this.running || !this.argv) return;
            const argv = this.argv.slice();
            if (this.withNote) {
                const note = $("sm-dialog-input").value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 200);
                if (note) argv.push("--note", note);
            }
            this.running = true;
            const log = $("sm-dialog-log");
            log.hidden = false;
            const b = $("sm-dialog-confirm");
            b.disabled = true;
            b.classList.add("is-busy");
            b.querySelector(".sm-btn-label").textContent = t("dlg.running");
            $("sm-dialog-cancel").disabled = true;
            const finish = (text, ok) => {
                this.running = false;
                b.hidden = true;
                const cancel = $("sm-dialog-cancel");
                cancel.textContent = t("dlg.close");
                cancel.disabled = false;
                this.result(text, ok);
                safeLoad();
            };
            let proc;
            try {
                proc = spawn(argv, "require");
            } catch (ex) {
                finish(t("dlg.error", { msg: (ex && ex.message) || String(ex) }), false);
                return;
            }
            proc.stream((text) => { log.textContent += text; log.scrollTop = log.scrollHeight; });
            proc.then(() => finish(t("dlg.success"), true)).catch((ex) => {
                ex = ex || {};
                if (isNoAdmin(ex)) finish(t("dlg.noAdmin"), false);
                else if (typeof ex.exit_status === "number") finish(t("dlg.failed", { code: ex.exit_status }), false);
                else finish(t("dlg.error", { msg: ex.message || ex.problem || String(ex) }), false);
            });
        },
    };
    const PORT_KEY = /^[0-9]{1,5}\/(tcp|udp)$/;
    const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
    const KIND = /^[a-z][a-z-]{1,30}$/;

    // --- Init ------------------------------------------------------------------
    function applyStaticTexts() {
        document.documentElement.lang = LANG;
        document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
        document.querySelectorAll("[data-i18n-aria]").forEach((el) => { el.setAttribute("aria-label", t(el.dataset.i18nAria)); });
        document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => { el.setAttribute("placeholder", t(el.dataset.i18nPlaceholder)); });
        document.querySelectorAll("span[data-icon]").forEach((el) => { const i = icon(el.dataset.icon); if (i) el.replaceWith(i); });
    }

    applyStaticTexts();
    $("sm-refresh").addEventListener("click", scan);
    $("sm-tabs").addEventListener("click", (e) => {
        const b = e.target instanceof Element ? e.target.closest("[role=tab]") : null;
        if (!b) return;
        chooseTab(b.dataset.tab);
    });
    $("sm-tabs").addEventListener("keydown", (e) => {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        const tabs = visibleTabs();
        const i = tabs.indexOf(tab);
        const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
        chooseTab(next, true);
        e.preventDefault();
    });
    document.addEventListener("click", (e) => {
        const target = e.target instanceof Element ? e.target : null;
        const el = target && target.closest("button");
        if (!el) return;
        const d = el.dataset;
        if (el.id === "sm-timer-setup") {
            dlg.open(t("dlg.install.title"), t("dlg.install.desc"), t("btn.setup"), [HELPER, "install", "timer"]);
        } else if (el.id === "sm-timer-off") {
            dlg.open(t("dlg.remove.title"), t("dlg.remove.desc"), t("btn.switchOff"), [HELPER, "remove", "timer"]);
        } else if (d.expectPort && PORT_KEY.test(d.expectPort)) {
            dlg.open(t("dlg.expect.title", { what: t("what.port", { port: d.expectPort }) }), t("dlg.expect.desc"), t("btn.expect"),
                     [HELPER, "expect", "port", d.expectPort], true);
        } else if (d.unexpectPort && PORT_KEY.test(d.unexpectPort)) {
            dlg.open(t("dlg.unexpect.title", { what: t("what.port", { port: d.unexpectPort }) }), t("dlg.unexpect.desc"), t("btn.unexpect"),
                     [HELPER, "unexpect", "port", d.unexpectPort]);
        } else if (d.expectContainer && NAME.test(d.expectContainer) && KIND.test(d.kind || "")) {
            dlg.open(t("dlg.expect.title", { what: t("what.container", { finding: t("kind." + d.kind), container: d.expectContainer }) }),
                     t("dlg.expect.desc"), t("btn.expect"), [HELPER, "expect", "container", d.expectContainer, d.kind], true);
        } else if (d.unexpectContainer && NAME.test(d.unexpectContainer) && KIND.test(d.kind || "")) {
            dlg.open(t("dlg.unexpect.title", { what: t("what.container", { finding: t("kind." + d.kind), container: d.unexpectContainer }) }),
                     t("dlg.unexpect.desc"), t("btn.unexpect"), [HELPER, "unexpect", "container", d.unexpectContainer, d.kind]);
        }
    });
    $("sm-dialog-confirm").addEventListener("click", () => dlg.run());
    $("sm-dialog-cancel").addEventListener("click", () => dlg.close());
    $("sm-dialog").addEventListener("cancel", (e) => { if (dlg.running) e.preventDefault(); });
    // cockpit.js has both events; a stand-in for it may leave them out.
    if (typeof cockpit.addEventListener === "function") {
        cockpit.addEventListener("locationchanged", onLocation);
        cockpit.addEventListener("visibilitychange", goToPlace);
    }
    onLocation();
    renderTabs();
    // Cockpit loads this page hidden right after the login, for the status icon in
    // its menu (menu-status.js). What reads or runs on the server, the root helper
    // and the first check above all, starts only once the page is shown.
    function start() {
        renderSignature();
        reloadOnChange(cockpit.file(STATUS_PATH, { syntax: JSON }));
        safeLoad();
    }
    const menu = window.SecurityMonitorMenuStatus;
    if (menu) menu.shown.then(start);
    else start();

    cockpit.transport.wait(function () {});
})();
