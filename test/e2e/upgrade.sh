#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The upgrade test of Security Monitor, on a throw-away runner with systemd (CI, test workflow,
# job upgrade; never a machine you use). The previous release, as its GitHub release serves it
# (test/e2e/release-asset.sh), runs with its timer on, a mark and its scans; then the package of
# this build goes over it with apt, as an update from the package repository does.
#
#   sudo env OUT=upgrade-session BOARD=board NODE=/path/to/node sh test/e2e/upgrade.sh OLD.deb NEW.deb
#
# BOARD is a checkout of Status Board at the release the workflow names: its src/lib/status.js
# judges the status as the board does (test/e2e/board-rules.js, run with NODE). The machine gets
# a public address on a dummy interface (pub0 203.0.113.10/24, the scan's "internet", as in
# test/e2e/setup.sh), UFW on with incoming denied and 5432/tcp and 6379/tcp allowed, and a
# listener on each of them at that address, which the scan rates a danger from the internet.
#
# What it shows (docs/INTERNALS.md, "Tests"):
#   - the previous release writes state.json and status.json, 6379/tcp marked as expected in
#     exposure.conf, the timer on; its status has no checks and no findings yet;
#   - after the upgrade exposure.conf and the timer are as they were; the scan the upgrade starts
#     writes first_seen (the time of that scan, for the marked port too) and a status with
#     features, checks and findings: 5432/tcp a finding with that time as its first sighting,
#     6379/tcp none while it is marked; the next scan keeps the times;
#   - the status as nobody, judged by Status Board's own rules: readable, nothing dropped;
#   - removing the package keeps exposure.conf and removes the state.
# Writes OUT/report.md and the raw answers. Exit 1 at the first step that fails.
set -eu
usage="usage: upgrade.sh OLD.deb NEW.deb (BOARD, NODE and OUT in the environment)"
old=${1:?$usage}
new=${2:?$usage}
board=${BOARD:?$usage}
node=${NODE:-node}
case $old:$new in
    *.deb:*.deb) ;;
    *) echo "upgrade.sh: two .deb, not $old and $new" >&2; exit 64 ;;
esac
# apt takes a local package by its path.
case $old in /*) ;; *) old=$PWD/$old ;; esac
case $new in /*) ;; *) new=$PWD/$new ;; esac
out=${OUT:-upgrade-session}
mkdir -p "$out"
report=$out/report.md
here=$(cd "$(dirname "$0")" && pwd)
apt_get="$here/../../tools/apt-get.sh"
helper=/usr/lib/cockpit-security-monitor/security.py
lib=/var/lib/cockpit-security-monitor
marks=/etc/cockpit-security-monitor/exposure.conf
service=cockpit-security-scan.service
timer=cockpit-security-scan.timer
public=203.0.113.10
# The hash of the marks file, outside OUT.
keep=/run/sm-upgrade
step=0
echo "# Security Monitor: upgrade" > "$report"

ok() { echo "- ok: $*" | tee -a "$report"; }
fail() { echo "- FAILED: $*" | tee -a "$report"; exit 1; }
next() { step=$((step + 1)); printf '\n## %s. %s\n\n' "$step" "$*" | tee -a "$report"; }
note() { echo "  $*" | tee -a "$report"; }
# EXPR over the JSON in FILE, as d.
json() { python3 -c "import json, sys; d = json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {'d': d}))" "$1" "$2"; }
installed() { dpkg-query -W -f '${Version}' cockpit-security-monitor; }
# The status verb of the manifest, as nobody, in English, to OUT/NAME.json.
status_as_nobody() {
    runuser -u nobody -- "$helper" status --lang en > "$out/$1.json" || fail "the status verb as nobody ($1)"
}
# Waits up to 180 seconds until the scan service is idle and state.json was generated at or after
# the time $1 (as the scan writes it, ISO 8601 in UTC).
scanned_since() {
    i=0
    while :; do
        if [ "$(systemctl show -p ActiveState --value "$service")" != activating ] && [ -f "$lib/state.json" ] &&
            python3 -c 'import json, sys; sys.exit(json.load(open(sys.argv[1])).get("generated", "") < sys.argv[2])' \
                "$lib/state.json" "$1" 2> /dev/null; then
            return 0
        fi
        i=$((i + 1))
        [ "$i" -le 180 ] || return 1
        sleep 1
    done
}

next "a public address, UFW with 5432/tcp and 6379/tcp allowed, a listener on each"
ip link add pub0 type dummy
ip addr add "$public/24" dev pub0
ip link set pub0 up
command -v ufw > /dev/null || sh "$apt_get" install ufw
ufw --force reset > /dev/null
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow 5432/tcp comment 'upgrade test listener' > /dev/null
ufw allow 6379/tcp comment 'upgrade test listener, marked' > /dev/null
ufw --force enable > /dev/null
ufw status verbose > "$out/ufw.txt"
listeners=
trap 'kill $listeners 2> /dev/null || true' EXIT
for port in 5432 6379; do
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
while True:
    s.accept()[0].close()' "$public" "$port" &
    listeners="$listeners $!"
done
for _ in $(seq 1 20); do
    [ "$(ss -Htln "( sport = :5432 or sport = :6379 )" | wc -l)" = 2 ] && break
    sleep 1
done
[ "$(ss -Htln "( sport = :5432 or sport = :6379 )" | wc -l)" = 2 ] || fail "the listeners did not start"
ok "pub0 $public, UFW on (incoming denied, 5432/tcp and 6379/tcp allowed), listeners on $public:5432 and :6379"

next "the previous release: its timer on, 6379/tcp marked, a scan"
[ ! -e "$lib" ] && [ ! -e "$marks" ] || fail "Security Monitor was here before the test"
sh "$apt_get" install "$old"
before=$(installed)
note "installed: $before (from $(basename "$old"))"
[ "$before" = "$(dpkg-deb -f "$old" Version)" ] || fail "the previous release is not the one installed"
"$helper" install timer > "$out/install-timer.txt" 2>&1 || { cat "$out/install-timer.txt"; fail "install timer"; }
systemctl is-enabled --quiet "$timer" && systemctl is-active --quiet "$timer" || fail "the timer is not on"
"$helper" expect port 6379/tcp --note "marked before the upgrade" > "$out/expect.txt" 2>&1 ||
    { cat "$out/expect.txt"; fail "expect port 6379/tcp"; }
"$helper" scan > "$out/scan-before.txt" 2>&1 || { cat "$out/scan-before.txt"; fail "the scan of the previous release"; }
for f in state.json status.json; do [ -f "$lib/$f" ] || fail "no $lib/$f"; done
grep -qx 'port 6379/tcp marked before the upgrade' "$marks" || fail "the mark is not in exposure.conf"
mkdir -p "$keep"
chmod 700 "$keep"
sha256sum "$marks" > "$keep/marks.sha256"
marks_mode=$(stat -c '%a %U' "$marks")
note "exposure.conf: $marks_mode; $(grep -vc '^#' "$marks") line(s) besides comments"
[ "$(json "$lib/state.json" "'first_seen' in d")" = False ] || fail "the previous release writes first_seen already"
status_as_nobody status-before
note "status of $before as nobody: $(json "$out/status-before.json" "(d['state'], [(i['id'], i['state']) for i in d['items']])")"
[ "$(json "$out/status-before.json" "'features' in d or 'checks' in d")" = False ] ||
    fail "the previous release sends checks or findings already"
[ "$(json "$out/status-before.json" "[i['state'] for i in d['items'] if i['id'] == 'exposure']")" = "['danger']" ] ||
    fail "the previous release does not rate 5432/tcp a danger"
ok "state.json and status.json of $before, the mark in exposure.conf ($marks_mode), the timer on; no first_seen, no checks, no findings"

next "the package of this build over it"
t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sh "$apt_get" install "$new"
after=$(installed)
note "installed: $after (from $(basename "$new")) at $t0"
[ "$after" = "$(dpkg-deb -f "$new" Version)" ] || fail "the package of this build is not the one installed"
[ "$after" != "$before" ] || fail "no upgrade: the same version"
sha256sum -c --quiet "$keep/marks.sha256" || fail "exposure.conf changed"
[ "$(stat -c '%a %U' "$marks")" = "$marks_mode" ] || fail "the mode or the owner of exposure.conf changed"
systemctl is-enabled --quiet "$timer" || fail "the timer is no longer enabled"
systemctl is-active --quiet "$timer" || fail "the timer is no longer active"
ok "exposure.conf unchanged ($marks_mode), the timer on"

next "the first scan after the upgrade (started by the upgrade): first_seen, checks and findings"
scanned_since "$t0" || fail "no scan after the upgrade within 3 minutes"
cp "$lib/state.json" "$out/state-after.json"
generated=$(json "$lib/state.json" "d['generated']")
seen=$(json "$lib/state.json" "sorted((d.get('first_seen') or {}).items())")
note "state.json generated $generated; first_seen: $seen"
[ "$(json "$lib/state.json" "(d.get('first_seen') or {}).get('port.5432-tcp')")" = "$generated" ] ||
    fail "first_seen does not hold 5432/tcp with the time of the first scan"
[ "$(json "$lib/state.json" "(d.get('first_seen') or {}).get('port.6379-tcp')")" = "$generated" ] ||
    fail "first_seen does not hold the marked 6379/tcp with the time of the first scan"
status_as_nobody status-after
note "features: $(json "$out/status-after.json" "d.get('features')")"
note "checks: $(json "$out/status-after.json" "[(c['id'], c['state']) for c in d.get('checks', [])]")"
note "findings of exposure: $(json "$out/status-after.json" "[(f['fid'], f['state'], f.get('since')) for i in d['items'] if i['id'] == 'exposure' for f in i.get('findings', {}).get('list', [])]")"
[ "$(json "$out/status-after.json" "sorted(d.get('features', []))")" = "['checks', 'findings']" ] ||
    fail "the status does not name the features checks and findings"
[ "$(json "$out/status-after.json" "[c['id'] for c in d.get('checks', [])]")" = "['exposure', 'ssh', 'logins', 'containers', 'crowdsec', 'fail2ban']" ] ||
    fail "the status does not carry the six checks"
[ "$(json "$out/status-after.json" "[(f['state'], f.get('since')) for i in d['items'] if i['id'] == 'exposure' for f in i.get('findings', {}).get('list', []) if f['fid'] == 'port.5432-tcp']")" = "[('danger', '$generated')]" ] ||
    fail "5432/tcp is not a finding at danger with the first sighting of that scan"
[ "$(json "$out/status-after.json" "[f for i in d['items'] for f in i.get('findings', {}).get('list', []) if f['fid'] == 'port.6379-tcp']")" = "[]" ] ||
    fail "the marked 6379/tcp is a finding"
ok "first_seen with the time of the first scan for both ports; features, six checks, 5432/tcp a finding since then, the marked port none"

next "the status as nobody, judged by Status Board's own rules"
"$node" "$here/board-rules.js" "$board/src/lib/status.js" security "$out/status-after.json" > "$out/board-rules.txt" 2>&1 ||
    { cat "$out/board-rules.txt"; fail "Status Board does not take the status whole"; }
note "$(cat "$out/board-rules.txt")"
ok "readable by the board, no item, check or finding dropped"

next "the next scan keeps the first sightings"
"$helper" scan > "$out/scan-again.txt" 2>&1 || { cat "$out/scan-again.txt"; fail "the scan after the upgrade"; }
again=$(json "$lib/state.json" "sorted((d.get('first_seen') or {}).items())")
note "first_seen: $again"
[ "$again" = "$seen" ] || fail "the next scan changed first_seen"
[ "$(json "$lib/state.json" "d['generated']")" != "$generated" ] || fail "the scan did not write a new state"
status_as_nobody status-again
[ "$(json "$out/status-again.json" "[f.get('since') for i in d['items'] if i['id'] == 'exposure' for f in i.get('findings', {}).get('list', []) if f['fid'] == 'port.5432-tcp']")" = "['$generated']" ] ||
    fail "5432/tcp lost its first sighting"
ok "first_seen and the finding's first sighting unchanged"

next "remove the package"
DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq cockpit-security-monitor > /dev/null
if [ -e "$lib" ]; then fail "the state stayed: $(ls -A "$lib" | tr '\n' ' ')"; fi
sha256sum -c --quiet "$keep/marks.sha256" || fail "exposure.conf went or changed with the package"
if [ -e "/etc/systemd/system/timers.target.wants/$timer" ] || [ -L "/etc/systemd/system/timers.target.wants/$timer" ]; then
    fail "the timer is still enabled"
fi
if systemctl is-active --quiet "$timer"; then fail "the timer still runs"; fi
rm -rf "$keep"
ok "the state gone, exposure.conf kept, the timer gone"
echo "ALL STEPS PASSED" | tee -a "$report"
