// SPDX-License-Identifier: Apache-2.0
/* Security Monitor, a Cockpit add-on: the status icon next to the menu entry, and
 * the moment the page itself starts.
 *
 * A page can set the status of its own menu entry only: Cockpit's shell files
 * cockpit.transport.control("notify", {page_status}) under the page of the frame
 * that sends it. So manifest.json asks Cockpit to load this page right after the
 * login ("preload", as Cockpit's own Software updates page does), hidden, and this
 * file reads nothing but /var/lib/cockpit-security-monitor/status.json, which every
 * scan and every mark writes for the status contract (docs/INTERNALS.md,
 * "`status.json` and `security.py status`"; 0644, so it works without
 * administrative access too). It judges it as the Status Board does: never better
 * than an item, an item older than its stale_after (an hour) at least a warning;
 * then
 *   danger -> "error", warning -> "warning", info -> "info", ok and none: no icon.
 * The tooltip is the summary in the session language (German from the file's
 * "i18n"), with the time when it is out of date; checked again the moment an item
 * turns out of date.
 *
 * security.js (the state, the signature, the first check) waits for `shown`: the
 * first time the page is shown. cockpit.hidden can be trusted once a first answer
 * is back: the shell sends a hidden frame its hint right after "init" (Cockpit 264
 * to 360), and messages from the shell arrive in order.
 */
(function () {
    "use strict";

    const STATUS_PATH = "/var/lib/cockpit-security-monitor/status.json";
    const TYPES = { danger: "error", warning: "warning", info: "info" };   // Cockpit's page status types
    const SEVERITY = { danger: 0, warning: 1, info: 2 };
    const ZONED_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/;
    const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

    const I18N = window.SecurityMonitorI18n;
    const LANG = /^de([-_]|$)/i.test(String(cockpit.language || "")) ? "de" : "en";    // as security.js
    const LOCALE = LANG === "de" ? "de-DE" : "en-GB";

    function t(key, vars) {
        let s = I18N[LANG][key];
        if (s === undefined) s = I18N.en[key];
        return s.replace(/\{(\w+)\}/g, (m, k) => (vars && k in vars ? String(vars[k]) : m));
    }

    // When the items turn out of date: { since, due } (ms) of the item that went first, or null.
    function outdated(doc, now) {
        let since = null, due = null;
        (Array.isArray(doc.items) ? doc.items : []).forEach((it) => {
            if (!it || typeof it !== "object") return;
            const at = typeof it.checked_at === "string" && ZONED_RE.test(it.checked_at) ? Date.parse(it.checked_at) : NaN;
            const after = it.stale_after;
            if (isNaN(at) || !Number.isInteger(after) || after <= 0) return;
            if (now - at > after * 1000) since = since === null ? at : Math.min(since, at);
            else due = due === null ? at + after * 1000 : Math.min(due, at + after * 1000);
        });
        return { since, due };
    }

    // The menu's status for a status.json at `now` (ms): {type, title}, or null for no icon.
    function statusOf(doc, now) {
        if (!doc || typeof doc !== "object" || doc.schema !== 1 || !Array.isArray(doc.items)) return null;
        let worst = own(SEVERITY, doc.state) ? doc.state : null;
        doc.items.forEach((it) => {
            if (it && typeof it === "object" && own(SEVERITY, it.state) &&
                (worst === null || SEVERITY[it.state] < SEVERITY[worst])) worst = it.state;
        });
        const { since } = outdated(doc, now);
        if (since !== null && (worst === null || SEVERITY[worst] > SEVERITY.warning)) worst = "warning";
        if (worst === null) return null;
        const de = LANG === "de" && doc.i18n && doc.i18n.de && typeof doc.i18n.de.summary === "string" ? doc.i18n.de.summary : null;
        const summary = (de !== null ? de : typeof doc.summary === "string" ? doc.summary : "").slice(0, 200);
        if (since === null) return { type: TYPES[worst], title: summary };
        const when = new Date(since).toLocaleString(LOCALE, { dateStyle: "medium", timeStyle: "short" });
        return { type: TYPES[worst], title: t("menu.stale", { summary, when }) };
    }

    // Sent only when it changed; the first time always (a reloaded frame may
    // find the shell still showing what it sent before).
    let sent;
    function notify(status) {
        const json = JSON.stringify(status);
        if (json === sent) return;
        sent = json;
        cockpit.transport.control("notify", { page_status: status });
    }

    // Again when an item turns out of date, should no new file come before.
    let timer = null;
    function render(doc) {
        window.clearTimeout(timer);
        const now = Date.now();
        notify(statusOf(doc, now));
        const { due } = doc && typeof doc === "object" ? outdated(doc, now) : { due: null };
        if (due !== null) timer = window.setTimeout(() => render(doc), Math.min(due - now + 1000, 86400000));
    }

    let answered;
    const firstAnswer = new Promise((resolve) => { answered = resolve; });

    // Every scan and every mark writes the file anew; a missing or unreadable one shows no icon.
    cockpit.file(STATUS_PATH).watch((content) => {
        let doc = null;
        try {
            doc = content ? JSON.parse(content) : null;
        } catch (e) {
            doc = null;
        }
        render(doc);
        answered();
    });
    // Should no answer come at all, the shell's hint has long arrived by then.
    cockpit.transport.wait(() => window.setTimeout(answered, 3000));

    const shown = firstAnswer.then(() => new Promise((resolve) => {
        function check() {
            if (cockpit.hidden) return;
            cockpit.removeEventListener("visibilitychange", check);
            resolve();
        }
        cockpit.addEventListener("visibilitychange", check);
        check();
    }));

    window.SecurityMonitorMenuStatus = { shown, statusOf };
})();
