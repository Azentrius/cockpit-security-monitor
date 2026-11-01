# Internals: interfaces, formats, flows

Reference for everyone working on the code. The helpers are the **only** bridge between the browser
and root. Whoever changes a format changes helper, page, fixtures (`test/fixtures/`), tests and this
document together; the page tolerates fields it does not know.

## Paths

| Path | Content | Owner / mode |
|---|---|---|
| `/usr/share/cockpit/security/` | the page (package `cockpit-security-monitor`) | root, 644 |
| `/usr/lib/cockpit-security-monitor/` | helpers: `security-scan.py`, `security.py`, `security-hetzner.py` (755); `seclib.py`, `secfw.py`, `seccheck.py`, `secstatus.py`, `secproc.py` (644) | root |
| `/usr/lib/systemd/system/cockpit-security-scan.{service,timer}` | the scan and its timer (every 15 minutes, `*:04/15`); the timer is off until `security.py install timer` | root, 644 |
| `/usr/lib/systemd/system/cockpit-security-hetzner.service` | the request to Hetzner's API; skipped without a token | root, 644 |
| `/var/lib/cockpit-security-monitor/state.json` | the state with every detail (addresses, rules, user names), and when each port the internet reaches was first seen | root, **600** (folder 755) |
| `/var/lib/cockpit-security-monitor/status.json` | the status for the Status Board: numbers, states, ports, service and container names, how each check went, a finding per port the internet reaches | root, 644 |
| `/var/lib/cockpit-security-hetzner/hetzner.json` | the answer of the Hetzner service (systemd's `DynamicUser`, kept below `/var/lib/private`) | the service's user, 600 |
| `/etc/cockpit-security-monitor/exposure.conf` | findings marked as expected (below) | root, 644; `.bak` the previous version |
| `/etc/cockpit-security-monitor/hetzner.token` | the read-only Hetzner Cloud API token (optional, set up by hand) | root, **600** |
| `/run/cockpit-security-monitor-scan.lock`, `…-marks.lock` | `flock` locks of a scan and of a change to the marks | root |

Files of the add-on in folders of others carry the prefix `cockpit-security-` (the units, the
Hetzner state folder).

## Calls from the page

| What | Call | Kind | Output |
|---|---|---|---|
| the state | `security.py show`, `superuser: "try"` | read (root: state.json is 0600) | one JSON object, below; exit 77 without administrative access |
| the summary without administrative access | `security.py status --lang en\|de`, `superuser: "try"` | read, no root | the status document |
| changes | `cockpit.file(status.json).watch()` | read | reloads when the tag changes (every scan and every mark writes the file) |
| the menu icon | `cockpit.file(status.json).watch()` in `menu-status.js`, no superuser | read (the file is 0644) | `cockpit.transport.control("notify", {page_status})`, below |
| "Refresh" | `security.py scan`, `superuser: "require"` | runs the service, waits | text, two languages |
| the regular check | `security.py install timer` / `remove timer`, `superuser: "require"`, through the dialog | changes the add-on's timer | text, live |
| "Mark as expected" | `security.py expect port 8080/tcp [--note TEXT]`, `… expect container NAME FINDING [--note TEXT]`, `superuser: "require"`, through the dialog | writes exposure.conf, then status.json again | text |
| "Remove mark" | `security.py unexpect port 8080/tcp`, `… unexpect container NAME FINDING` | the same | text |

`SECURITY_LANG=de|en` (environment) selects the language of `security.py`'s messages. Every
argument is checked in the helper: a port `^[0-9]{1,5}/(tcp|udp)$` (1 to 65535), a container name
`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, a finding from the fixed list, a note of at most 200
characters without control characters. Anything else exits 64.

### `security.py show`

```json
{"root": true, "state": {…state.json with the marks applied…}, "marks_problem": null,
 "marks_file": "/etc/cockpit-security-monitor/exposure.conf", "timer": "active|inactive|missing",
 "next": "2026-10-20T12:19:00Z", "running": false, "hetzner_token": false}
```

`state` is `null` before the first scan (the page then checks once by itself). `marks_problem`:
`null`, `"untrusted"` (the file is not root's or others can write it: its marks do not count), or
`"lines 3,7"` (lines that could not be read). With the marks applied a marked port has
`expected` (the note) and `state` `info`, its old state in `base_state`; a marked container finding
has `expected` and `state` `ok`.

### Exit codes of `security.py`

| Code | Meaning |
|---|---|
| 0 | ok (findings are no error) |
| 1 | failed (the scan service, systemctl, the state not readable) |
| 2 | a unit is missing |
| 5 | the marks file is not trusted; nothing changed |
| 64 | wrong call |
| 75 | busy (a scan, or a change of the marks) |
| 77 | needs root (`show`, `scan`, the timer, the marks); `status`: status.json exists but cannot be read |

## The scan

`cockpit-security-scan.service` runs `security-scan.py --output state.json --status status.json` as
root in the host's network namespace (it lists that namespace), with `IPAddressDeny=any`,
`IPAddressAllow=localhost` (cscli asks CrowdSec's local API), `RestrictAddressFamilies=AF_UNIX
AF_NETLINK AF_INET AF_INET6` and `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE
CAP_DAC_READ_SEARCH`, `ProtectSystem=strict`, `ProtectHome=read-only` and the usual rest
(`tools/check-units.sh` checks the exposure). It writes only its own folder. Under its lock it
first reads the previous state.json for `first_seen` (when each port the internet reaches was first
seen), carries it over and writes the new state.

Commands run through `secproc.run`: a list (never a shell), `PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
`LC_ALL=C`, `TZ=UTC`, a process group of its own and a deadline. The sources, in this order:

| Source (`sources.<name>`) | Read from | For |
|---|---|---|
| `ip` | `ip -j addr` | the interfaces and the class of each address |
| `ss` | `ss -H -tulpn`, `/proc/<pid>/cgroup` | listening sockets, their processes, the container of a process |
| `docker` | Docker's API over `/var/run/docker.sock`, GET only: `/info`, `/version`, `/containers/json`, `/containers/<id>/json`, `/networks` | published ports, container addresses and bridges, the firewall backend, the settings of each container |
| `rules` | `iptables-save`, `ip6tables-save` (and `iptables-legacy-save` when legacy tables are loaded), `nft -j list ruleset` | the packet filter |
| `ufw` | `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/ufw/user.rules`, `user6.rules` | UFW's state and rules in readable form |
| `hetzner` | `/var/lib/cockpit-security-hetzner/hetzner.json` (from the Hetzner service) | the Cloud Firewalls applied to this server |
| `sshd` | `/usr/sbin/sshd -T`, `/etc/ssh/sshd_config`, `sshd_config.d/*.conf` (Match blocks) | the effective configuration |
| `keys` | `/etc/passwd`, `/etc/shadow` (only as root), the authorized_keys files of accounts with a login shell (no link followed at the last step, regular files only, 1 MiB) | keys, options, who can change the file, accounts locked with `passwd -l` whose keys still log in |
| `journal` | `journalctl -o json --since=-14d` for `SYSLOG_IDENTIFIER` `sshd`, `sshd-session`, `sudo`, `cockpit-session`; `journalctl -o json --since=-14d --lines=+1` for where the journal begins (systemd 254 or newer, else unknown) | logins of the last 14 days, or since the journal begins |
| `crowdsec` | `systemctl is-active crowdsec.service`, `cscli version`, `cscli decisions list -o json`, `cscli alerts list -o json --since 14d`, `cscli bouncers list -o json`, the firewall bouncer's YAML, `online_api_credentials.yaml` | what CrowdSec does |
| `fail2ban` | only when `/usr/bin/fail2ban-client` exists: `systemctl show fail2ban.service -p ActiveState -p UnitFileState -p ActiveEnterTimestamp`, `fail2ban-client --version`, `ping`, `-d` (the configuration it runs, one Python literal per line, read with `ast.literal_eval`), and while it answers `status` and `status JAIL` (at most 30 jails); its SQLite database (`dbfile` from `-d`, default `/var/lib/fail2ban/fail2ban.sqlite3`, only a path below `/var/lib`) opened read-only (`mode=ro`: `bips` for the bans now, `bans` counted per jail for 14 days, never the column `data` with log lines); size and age of the jails' log files (`lstat`, never their content); `/etc/iptables/rules.v4` and `rules.v6` for `f2b-` chains; `/etc/services` for port names | what fail2ban does |

Each source has a `state`: `ok`, `missing` (not installed), `skipped` (`reason`), `needs-root`,
`partial` (`missing`: what; for `hetzner` `rules`, an applied firewall whose rules are not known;
for `fail2ban` the parts it could not read, `ping`, `config`, `status`, `jails`, `skipped`, `db`,
and `error`: the first reason), `error` (`error`: a short reason) or `timeout`.

The exposure rests on `ip`, `ss` and `rules`, and on `docker` when Docker's socket is there. Without
the addresses (`ip` not `ok`) no socket's classes are known: `network.public` is `null` per family,
and every port not bound to the loopback is unknown from the internet, the VPN and the private
network (`reason` `no-addresses`); a socket on the loopback stays "this host". Without the sockets
(`ss` neither `ok` nor `partial`) `ports` holds only what Docker publishes. Without the packet
filter every port is unknown (`no-rules`). When Docker's socket is there but Docker does not answer
(`docker` `error` or `needs-root`), no published port is known: a socket of `docker-proxy`, or one on
a port a DNAT rule of its family names (any destination), may be a port Docker forwards to a
container past the input rules, so it is unknown from the internet, the VPN and the private network
(`no-docker`) and never judged by the input rules; "this host" is judged as before. A port Docker
publishes without docker-proxy then has no socket and is not listed. The page and the status then
never say "nothing reachable".

### Why iptables-save and nft's JSON

iptables-nft keeps the matches of iptables extensions (`conntrack`, `multiport`, `addrtype`,
`recent`) as `xt` expressions, and `nft -j` names such an expression without its options
(`{"xt": {"type": "match", "name": "conntrack"}}`). The tables iptables manages (`filter`, `nat`,
`mangle`, `raw`, `security` in the families `ip` and `ip6`) are therefore read from iptables-save,
which prints them in full; nft's JSON supplies every other table (nftables.conf, Docker's nftables
mode, fail2ban, CrowdSec). When iptables is the legacy variant, nft's JSON is read whole.

### Address classes

From `ip -j addr`: `lo` is **local**; `wg*`, `tun*`, `tailscale*`, `zt*`, `nebula*` are the **VPN**;
`docker*`, `br-*`, `veth*` and other container bridges are left out; on every other interface a
public address (not private, CGNAT, link-local, multicast or reserved) is the **internet**, a
private one (RFC 1918, ULA) the **private network**. A host address (`/32`, `/128`, as in Hetzner's
private networks) stands for its private block. IPv4 and IPv6 are separate: a host without a
public IPv6 address has no "internet" for IPv6.

### The evaluator (`secfw.py`)

For each port, family and class, a new connection is followed through every base chain of type
`filter` at the hooks ingress (its device), prerouting and then input (a socket of the host) or
forward (a port Docker forwards to a container), in the order of their priorities:

- Each base chain ends in accept (a rule or the policy), drop (final, also `reject`) or unknown.
  The connection is let in when no chain drops it and none is unknown.
- Understood: addresses and sets of them (also named sets and ranges), ports and port lists,
  protocols, interfaces with wildcards, `ct state` (a new connection), the original destination
  and port (`--ctorigdst`, `--ctorigdstport`, `ct original`), `ct status dnat`, address types and
  `fib daddr type`, `limit` (a first packet passes), `recent --update/--rcheck` (a first
  connection is not in the list yet, so `ufw limit` lets it in), IPv6 routing headers (`-m rt`, a
  plain connection has none), jumps, goto, return, verdict maps.
- A match it cannot read (`-m mark`, an `xt` expression, an ipset other than as the source) is
  followed both ways to the end of the base chain; when both end the same, that is the answer,
  else the result is **unknown** with that rule. At most 64 such forks per connection.
- A source port (`--sport`, `--ports`, `th sport`) is the sender's choice: when one of the two ways
  lets the connection in, it is in. UFW's rule for DHCP replies (`--sport 67 --dport 68 -j
  ACCEPT`) lets in whoever sends from port 67.
- Sources are symbolic: "the internet" is every public address of the family, the VPN and the
  private network are their networks. A rule that names only part of a class (`-s
  198.51.100.0/24 -j ACCEPT`, `! -s 10.8.0.0/24 -j DROP`) gives a narrower sample that is
  followed on its own: when only such parts get in, the result is **restricted** with them as
  `sources` and the rule or policy that stops the class as a whole as `limited_by` (the page
  names it as what keeps everyone else out); when a part could get in but a rule for it cannot be
  read, the result is **unknown**.
  Parts of ban lists (a plain match that drops) are not followed.
- An ipset as the source (`-m set --match-set NAME src`, a country list in DOCKER-USER) is such a
  part, `ipset NAME` in `sources`: its members are not in iptables-save, so the page says
  "reachable only from ipset NAME" and does not guess who they are. Whether the members are in a
  network another rule names is not known either (unknown).

**Docker:** a published port (`NetworkSettings.Ports`) whose DNAT is in a nat chain (iptables-save or
nft) is followed on the forward path, after the DNAT: destination the container's address and port,
out through its bridge, the original destination kept. Without a DNAT for the family (IPv6 to a
container without an IPv6 address, or Docker started with `iptables=false`) the port is the
`docker-proxy` socket on the host and takes the input path. A connection from the host itself to a
published port counts as reachable.

**Hetzner Cloud Firewall:** applies to the internet class only (it filters the public interface).
A server with no firewall applied lets everything through. With firewalls applied, an incoming
connection needs a rule of its protocol and port in one of them (Hetzner joins their rules);
`source_ips` with `0.0.0.0/0` or `::/0` let the whole internet in, narrower public networks make it
restricted; otherwise it blocks. A firewall without incoming rules (`rules: []`) lets nothing in.
When it blocks, the port's result is closed and `host_result` keeps what the host alone would
allow. A firewall applied to the server whose rules are not known (`rules: null`: missing from the
API's answer) may let anything in, so it never counts as protection: the answer for the port is
`unknown` (its `refs` those firewalls) and the host's result stands, as without an answer. Only a
known rule that lets the whole internet in still decides (`allows`), as it claims no protection.

### Assessment of a port (spec 4.2)

| Case | `state` | `why` |
|---|---|---|
| reachable from the internet, no filter on the host for that family (`input_filter` off, a probe on tcp/64999) and no Hetzner answer for the port (no token, or the rules of an applied firewall not known) | warning | `outside-only` |
| reachable from the internet: databases, Docker's API, Cockpit, SSH and the other ports in `seclib.KNOWN_PORTS` with weight danger | danger | `public-danger` |
| reachable from the internet: 80, 443 (also UDP), 51820/udp, a UDP port of the kernel on a host with a VPN interface, the DHCP client (68/udp, 546/udp) | info | `public-expected` |
| reachable from the internet: anything else | warning | `public-other` |
| reachable only from part of the internet | info (danger ports: warning) | `restricted` |
| unknown from the internet (a rule this page cannot read, the packet filter or the addresses not read, or Docker not answering for a port it may publish) | none | `unknown` |
| blocked by the Hetzner Cloud Firewall | ok | `hetzner` |
| reachable from the VPN and/or the private network only (or not known from there: never "only from the host") | ok | `only-vpn`, `only-private`, `only-vpn-private` |
| only from the host | ok | `local` |

A port marked as expected becomes `info` (`expected`, `base_state`).

## `state.json`

```json
{"format": 1, "generated": "2026-10-20T12:00:00Z", "took_ms": 1840, "root": true,
 "network": {"interfaces": [{"name": "eth0", "kind": "net", "up": true, "addrs": [{"addr": "203.0.113.10", "prefix": 32, "family": 4, "class": "internet"}]}],
             "public": {"4": true, "6": true}},
 "firewall": {"iptables": {"version": "1.8.10", "variant": "nf_tables"}, "tables": [{"src": "iptables", "family": "ip", "table": "filter", "chains": 42, "rules": 89, "owners": ["docker", "ufw"]}],
              "legacy_rules": false, "docker_user": {"4": 0, "6": 0}, "input_filter": {"4": "on", "6": "on"},
              "ufw": {"installed": true, "enabled": true, "loaded": {"4": true, "6": true}, "ipv6": true, "default_input": "drop", "default_forward": "drop", "rules": […], "rules_total": 8},
              "docker": {"version": "28.5.1", "backend": "iptables", "backend_known": true, "containers": 4},
              "hetzner": {"configured": false}},
 "ports": [{"id": "tcp-8080", "proto": "tcp", "port": 8080, "name": null, "weight": "warning",
            "service": {"kind": "docker", "containers": ["web"], "images": ["nginx:1.27-alpine"], "processes": ["docker-proxy"], "container_ports": [80]},
            "binds": ["0.0.0.0:8080", "[::]:8080"],
            "reach": {"4": {"internet": {"result": "open", "path": "forward", "iface": "eth0", "sources": [],
                                         "to": {"addr": "172.17.0.2", "port": 80, "rule": {…}},
                                         "steps": [{"chain": {"src": "iptables", "family": "ip", "table": "filter", "chain": "FORWARD", "policy": "drop", "owner": null},
                                                    "result": "accept", "policy": false,
                                                    "rule": {"src": "iptables", "family": "ip", "table": "filter", "chain": "DOCKER", "index": 1, "text": "-d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT", "comment": "", "owner": "docker"}}]},
                              "vpn": {…}, "private": {…}, "local": {…}},
                      "6": {…}},
            "state": "warning", "why": "public-other"}],
 "ssh": {"sshd": {"state": "ok", "match": []}, "findings": [{"key": "passwordauthentication", "value": "no", "state": "ok", "code": "password-off"}, …],
         "keys": [{"user": "root", "file": "/root/.ssh/authorized_keys", "mode": "600", "problems": [], "state": "ok",
                   "account": {"password": "none", "expired": false},
                   "keys": [{"line": 1, "type": "ssh-ed25519", "bits": 256, "fingerprint": "SHA256:…", "comment": "bastion", "options": ["from=\"10.8.0.0/24\""], "findings": [], "state": "ok"}]}],
         "counts": {"keys": 4, "files": 2}, "ports": ["22"], "listen": [], "state": "warning"},
 "logins": {"state": "ok", "entries": 9, "success": [{"time": "…", "service": "ssh", "method": "publickey", "user": "root", "source": "10.8.0.2", "class": "vpn"}],
            "success_total": 3, "failed": [{"source": "10.8.0.9", "class": "vpn", "count": 1, "last": "…", "services": ["ssh"], "users": 1}],
            "failed_sources": 1, "failed_total": 1, "sudo": [{"user": "alex", "uses": 1, "failures": 1, "last": "…"}],
            "outside": 0, "truncated": false, "journal_start": "2026-10-11T08:00:00Z", "assessment": "ok"},
 "containers": {"state": "ok", "items": [{"name": "runner", "image": "…", "findings": [{"kind": "docker-socket", "state": "danger", "detail": "/var/run/docker.sock"}]}]},
 "crowdsec": {"installed": false},
 "fail2ban": {"installed": true, "version": "1.0.2", "active": "active", "running": true, "since": "2026-10-18T08:00:00Z",
              "unit_file": "enabled", "dbpurgeage": "1d", "state": "warning",
              "findings": [{"code": "unmanaged-bans", "state": "warning", "value": 1, "chains": ["f2b-sshd"]}], "incomplete": [],
              "jails": [{"name": "web", "backend": "auto", "logs": [{"path": "/var/log/web/access.log", "exists": true, "size": 48000, "mtime": "…"}],
                         "journal": null, "maxretry": 3, "findtime": "10m", "bantime": "10m", "failregex": 1, "running": true,
                         "actions": [{"name": "nftables", "port": "8080,443", "protocols": ["tcp"], "allports": false, "kind": "nftables",
                                      "where": ["hook input"], "forward": false, "observed": true}],
                         "failed_now": 0, "failed_total": 12, "banned_now": 1, "banned_total": 3, "history": 3,
                         "findings": [{"code": "input-only", "state": "warning", "value": "8080/tcp"}], "state": "warning"}],
              "bans": [{"ip": "192.0.2.80", "class": "internet", "jail": "web", "since": "…", "until": "…", "count": 2}],
              "bans_total": 1, "history_total": 3, "history_days": 14, "errors": {}},
 "sources": {"ip": {"state": "ok", "took_ms": 3}, …},
 "first_seen": {"port.443-tcp": "2026-10-12T08:04:00Z", "port.8080-tcp": "2026-10-20T12:00:00Z"}}
```

- `format`: 1. A page that knows a lower format says so.
- `first_seen`: when the scan first saw each port at `info` or above (the whole internet reaches
  it, or only some addresses), by the `fid` of its finding in the status (`port.<port>-<proto>`).
  Before the marks: a marked port keeps its time, so it is right again once the mark is taken back.
  A port still there keeps the time of the previous state; a new one gets the time of this scan
  (`generated`). One that is gone is dropped only when the check `exposure` is `checked`: after a
  scan that could not read everything (see the checks under `status.json`) a port missing from it is
  not known to be gone, and its time stays. Entries of the previous state that are not of that form,
  or lie after this scan, are left out. A state without it (written before) gives findings without
  `since`.
- `network.public.<family>`: `true` (a public address), `false` (none), `null` (not known: `ip -j
  addr` failed).
- `reach.<family>.<class>.result`: `open`, `restricted` (+ `sources`: networks, or `ipset NAME`;
  `limited_by`: the step, in the form of `steps`, that drops the rest of the class), `closed`,
  `unknown` (+ `unknown`: the step with the rule), `absent` (no address of that family and class
  receives the socket). `path`: `input` or `forward` (+ `to`); `proxy`: true for docker-proxy;
  `reason`: `local-published` (the host to a published port), `no-rules` (the packet filter could
  not be read), `no-addresses` (the addresses could not be read), `no-docker` (Docker did not
  answer, and the socket may be a port it publishes). `steps` keep the base chains that
  decided (a rule, or the policy); for `restricted` they are the way of an allowed source. A port
  only the Hetzner Cloud Firewall restricts has no `limited_by` (see `hetzner`).
- `reach.<family>.internet.hetzner` (with a Hetzner answer, for a port the host lets in or cannot
  judge): `result` `none` (no firewall applied), `allows`, `restricted` (+ `sources`), `blocks` or
  `unknown` (the rules of an applied firewall not known); `refs` the firewalls (`firewall` its name,
  empty when the API did not list it, `id`) and for `allows` and `restricted` the rule.
- Container findings: `docker-socket` (danger, also read-only: `:ro` protects the file, not the
  API), `privileged`, `pid-host`, `cap-add` (`SYS_ADMIN`, `NET_ADMIN`, `ALL`), `host-mount` (`/`,
  `/etc`, `/root`, `/var/run`, `/run` writable) (warning), `network-host`, `root-user`,
  `no-new-privileges`, `apparmor-unconfined` (info).
- SSH codes: `password-on|off`, `kbd-pam|off|no-pam`, `empty-passwords`, `root-yes|key|forced|no`,
  `pubkey-on|off`, `tries-many|ok`, `allow-list`, `no-allow-list`, `x11-on|off`, `agent-on|off`.
  Keys: `dsa`, `rsa-short` (under 3072 bits) (warning), `no-from` (info), `unreadable`. Files:
  `file-writable`, `dir-writable`, `file-owner`, `dir-owner` (warning), `link` (not read).
  `sshd.reason` `privsep-dir-missing`: `/run/sshd` is missing (socket-activated sshd), so `sshd
  -T` cannot run; the page shows the line for `tmpfiles.d` (decision 9.6: set up by hand).
- `ssh.keys[].account` (only when the scan could read `/etc/shadow`, i.e. as root):
  `password` `locked` (a `!` in front of a real hash: `passwd -l`, `usermod -L`), `none` (`!`,
  `!!`, `*`, `!*`: never had a password, a key-only account by design), `empty` or `set`;
  `expired` from the account's expiry date. `finding: "locked-with-keys"` (warning, also on the
  file's `state`) for a locked, not expired account with keys while sshd uses PAM: with `UsePAM
  yes` sshd does not check the lock, so the keys still log in (`usermod --expiredate 1` stops
  them). Not for root: a locked root password with keys is how Ubuntu sets up root.
- `logins.success[].class` and `failed[].class`: `internet`, `vpn`, `private`, `local`, `cgnat`,
  `link`, `other`; `null` for Cockpit sessions (Cockpit does not log their source on the target).
  Failed attempts count once per connection (process). At most 200 successes and 100 sources.
  `logins.journal_start`: the oldest entry within the 14 days, `null` when unknown. When it lies
  more than a day after the start of the 14 days (rotation), the page and the status name that day
  instead of "14 days".
- CrowdSec findings: `old-engine` (before 1.5), `not-running`, `bouncer-input-only` (nftables mode
  without the hook forward), `bouncer-no-docker-user` (iptables mode without DOCKER-USER), both only
  when Docker publishes ports, and `no-bouncer`.
- fail2ban: `{"installed": false}` when `fail2ban-client` is missing. `active` and `unit_file` come
  from systemctl, `running` is true when `fail2ban-client ping` answers, `since` is when the unit
  became active. A jail is listed when the configuration (`-d`) or `status` names it; `running`:
  `true` when `status` lists it, `false` when the list does not (or fail2ban does not run), `null`
  when the list could not be read; `error`: why `status JAIL` failed for it; `skipped`: true for a
  running jail past the first 30 in fail2ban's list, which is not asked (no counters). `backend` as
  configured (`systemd…` reads the journal: `journal` holds its matches, `logs` stays empty);
  `logs[]` with `exists`, `size` and `mtime`; `maxretry`, `findtime`, `bantime` as fail2ban gives
  them (a number or a text such as `10m`); `failregex` the number of its patterns; `failed_now`,
  `failed_total`, `banned_now`, `banned_total` the counters of `status JAIL` since the jail started
  (`null` when it does not run or did not answer); `history` its bans in `history_days` (14) from
  the database.
- fail2ban, what could not be read: `incomplete` lists the parts the assessment needs that are
  missing, in this order: `ping` (the unit is active, or the call hangs, but `fail2ban-client ping`
  gives no answer: not known whether it runs, which is not `not-running`), `config` (`-d`),
  `status` (the list of running jails), `jails` (`status JAIL` failed for one, see its `error`),
  `skipped` (fail2ban runs more than 30 jails, and those past the first 30 were not asked, see
  their `skipped`). Then the state of fail2ban, and of each jail it concerns, is `none` (not
  checked) unless a finding is `info` or above; a jail is `ok` only when it runs, answered and its
  configuration was read. The database is optional: without it (`errors.db`) only `history`, `history_total` and the
  times of the bans are missing, and the state stands. `bans_total` is `null` when neither every
  running jail nor the database could say who is banned.
- fail2ban's actions: `kind` `iptables`, `nftables` or `other` (any other action, not judged:
  `where` empty, `forward` `null`); `port` and `protocols` from the action's options (`allports`
  for a ban of every port). `where` is the chain the packet filter jumps to `f2b-NAME` from
  (iptables) or the hook of nftables' `f2b-chain`, when the packet filter has them (`observed`);
  before its first ban iptables has no chain yet, and the action's options decide (`chain`,
  default INPUT; `chain_hook`, default input). `forward` is true for FORWARD, DOCKER-USER, the hook
  forward or prerouting.
- fail2ban's bans: `bans[]` are the rows of `bips` that have not expired (`until` `null`: a ban
  without end), at most 100, with `count` from fail2ban; `bans_total` counts them all. When the
  database gives none, they come from `status JAIL`, without times. `history_total` is the sum of
  the jails' `history`, `null` without the database. `errors` names what could not be read
  (`ping`, `config`, `status`, `db`) with a short reason.
- fail2ban's findings per jail, each with `value`: `input-only` (warning: a port of the jail that
  Docker publishes to the internet, the ban not in front of the forwarding; `value` the ports, at
  most 6), `allports-input` (note: the same for an all-ports ban), `udp-open` (warning: TCP only
  while one of its ports is open for UDP from the internet; the UDP ports), `log-missing` (warning:
  the path), `log-idle` (warning: unchanged for 3 days; the path, `days`), `no-match` (warning: a
  file log that is not empty, 0 hits, fail2ban running for more than a day; `value` the start),
  `jail-not-running` (warning, no `value`: in the configuration, while fail2ban answers and its list
  of running jails lacks it). For the whole: `not-running` (warning; the unit's state; a jail of a
  fail2ban that does not run has no finding of its own), `unmanaged-bans` (warning: addresses in
  `f2b-` chains or `addr-set-` sets that fail2ban does not hold as banned, by the lists of its
  jails or else its database, not judged without both; their number, `chains`),
  `persisted-chains` (note: `f2b-` lines in a saved ruleset; the file).

## The marks (`/etc/cockpit-security-monitor/exposure.conf`)

```
# comments
port 8080/tcp Rustdesk relay, reachable on purpose
container forgejo-runner docker-socket The CI runner needs the socket
```

One line each: `port <port>/<tcp|udp> <note>` or `container <name> <finding> <note>`. The file
counts only when it is a regular file of root that nobody else can write. "Mark as expected" writes
it atomically (a copy of the previous version as `exposure.conf.bak`) under a lock, keeps lines
written by hand, and writes status.json again from the last state, so the Status Board shows the
change at once. Nothing else is written; no firewall rule is ever touched.

## The Hetzner service

`cockpit-security-hetzner.service` runs `security-hetzner.py --output
/var/lib/cockpit-security-hetzner/hetzner.json` with `DynamicUser=yes` (no root), network, and the
token from `LoadCredential=hetzner.token:/etc/cockpit-security-monitor/hetzner.token`; it is skipped
without the file. It asks `GET https://api.hetzner.cloud/v1/servers` and `/v1/firewalls` (50 per
page, at most 20 pages), finds the server whose public IPv4 address, or IPv6 network, is an address
of this host (`ip -j addr`), and keeps the incoming rules of the firewalls in its
`public_net.firewalls`:

```json
{"format": 1, "tried_at": "2026-10-20T11:59:00Z", "ok_at": "2026-10-20T11:59:00Z", "error": null,
 "server": {"id": 4711, "name": "web-1"}, "matched_by": "ipv4",
 "firewalls": [{"id": 38, "name": "web", "status": "applied",
                "rules": [{"direction": "in", "protocol": "tcp", "port": "80", "source_ips": ["0.0.0.0/0", "::/0"], "description": "HTTP"}]}]}
```

A firewall the server names but `/v1/firewalls` does not list is kept with `name` and `rules`
`null`: its rules are not known (not `[]`, which blocks everything), and the scan counts it as no
protection (see the evaluator).
When a request fails, the last good answer stays and `error` and `tried_at` are added; the scan
then calls the state `stale` and the page says how old it is. The token is never written anywhere
and never printed. The format of the API is taken from Hetzner's documentation and the hcloud-python
client (`test/fixtures/hetzner-open/hetzner-api/`); no answer of a real project is recorded yet.

## `status.json` and `security.py status` (status contract)

The status format all Azentrius add-ons share (schema 1, `cockpit-status-board/docs/STATUS-CONTRACT.md`).
`manifest.json` names the command: `"azentrius": {"status": ["/usr/lib/cockpit-security-monitor/security.py", "status"]}`.
The verb reads status.json only: no root, no command, no lock, no network. `--lang` takes a
language tag (German for `de…`, English for every other); anything else exits 64; a file that
exists but cannot be read exits 77. Without the file the state is `none` ("Not checked yet").

| `id` | State | `value` | `detail` |
|---|---|---|---|
| `exposure` | the most severe port; at least `info` when a port could not be assessed; `none` when the packet filter could not be read, and when the addresses or the listening sockets could not be read, or Docker could not be asked (its socket there), unless a port found is at least `info` | ports the whole internet reaches (left out when nothing was found and the addresses, sockets or Docker's answer are missing) | first what could not be read; those ports with their service, at most 5; then the ports only some addresses reach (`restricted`), at most 3; never "no port reachable" without the addresses, the sockets and Docker's answer |
| `ssh` | the most severe of the configuration and the keys; `none` when `sshd -T` failed and the keys could not be read | findings at warning or above | password login, root, locked accounts whose keys still log in (a count, no names), short or DSA keys, files others can change, keys without `from=`, or why `sshd -T` failed |
| `logins` | `warning` with a successful login from outside VPN and private networks, else `ok`; `none` when the journal could not be read | logins from outside, else failed attempts | counts, no addresses or names; "since DAY" instead of "in 14 days" when the journal begins later |
| `containers` | the most severe finding not marked; `none` when Docker could not be asked | containers with a warning or danger | the finding and container names, at most 3 per finding |
| `crowdsec` | only when installed: its findings, else `ok` | active decisions | its findings, then the number of active decisions |
| `fail2ban` | only when installed: the most severe finding, else `ok`; `none` when a part it needs (`incomplete`) could not be read and no finding is `info` or above | bans now (left out when not known) | first what could not be read (no answer to ping, the configuration, the running jails, the jails whose status failed, the number of jails past the first 30); the warnings with their jail (no addresses, no paths), else the number of jails and bans; last "history of bans not readable" when only the database is missing |
| `scan` | `ok`; `warning` when the state is older than an hour (decided when the verb runs) | | |

`stale_after` is 3600 for every item, `link` is `#/<id>` (no link for `scan`); a `detail` is cut
to 200 characters. The file holds the English document plus the German texts under `i18n.de`
(summary, titles and details) and the text for an out-of-date check in both languages
(`i18n.de.scan_old`, `i18n.en.scan_old`); the verb returns one language without `i18n`, with the
version of the installed page (`const VERSION` in `security.js`).

### Checks and findings

The answer also carries the optional parts of the contract ("Optional: checks, findings and a
host's profile"): `features: ["checks", "findings"]`, a check per area in `checks`, and the findings
of the item `exposure`.

```json
"features": ["checks", "findings"],
"checks": [{"id": "exposure", "state": "checked", "title": "Reachable from the internet", "item": "exposure",
            "checked_at": "2026-10-20T12:00:00Z", "stale_after": 3600},
           {"id": "ssh", "state": "partial", "title": "SSH", "item": "ssh",
            "reason": "sshd -T without its privilege separation directory: not checkable", …},
           {"id": "fail2ban", "state": "notapplicable", "title": "fail2ban", "reason": "fail2ban is not installed", …}],
"items": [{"id": "exposure", …, "findings": {"complete": true, "total": 5, "list": [
  {"fid": "port.8080-tcp", "state": "warning", "title": "8080/tcp web", "since": "2026-10-20T12:00:00Z",
   "exposure": "internet", "link": "#/exposure/8080-tcp"}, …]}}]
```

**Checks:** always all six, in this order: `exposure`, `ssh`, `logins`, `containers`, `crowdsec`,
`fail2ban`. `title` is the item's title, `item` the id of the item when the answer has one,
`checked_at` and `stale_after` as the items', `reason` (in the language asked for, cut to 200
characters) says why the check is not `checked`. A check is `checked` only when everything it rests
on was read:

| `id` | `checked` | `partial` | `failed` | otherwise |
|---|---|---|---|---|
| `exposure` | the packet filter, the addresses, the sockets with their processes, Docker's answer (its socket there) and the Hetzner Cloud Firewall (a token set) read, and every port assessed | one of them not read, also when only one of `iptables-save`, `ip6tables-save` and `nft` fails (a tool not installed is no gap), or a port not assessable, also a marked one (a mark does not assess it); the reason names each | | `unsupported`: neither `iptables-save` nor `nft` is installed |
| `ssh` | `sshd -T` and the keys of every account read | `sshd -T` failed while the keys were read, `/etc/passwd` not readable, or the keys of other accounts not readable (no root) | `sshd -T` failed and no key could be read | `notapplicable`: no `/usr/sbin/sshd`; `noaccess`: `sshd -T` needs root |
| `logins` | the journal read | only part of it (no root), or more than 100000 entries | `journalctl` failed or timed out | `unsupported`: no `journalctl` |
| `containers` | Docker answered | | Docker's socket is there, but Docker does not answer | `notapplicable`: no Docker socket; `noaccess`: the socket needs root |
| `crowdsec` | every list of `cscli` read | a list of `cscli` not read | | `notapplicable`: CrowdSec is not installed; `noaccess` |
| `fail2ban` | everything read | a part it needs (`incomplete`), or only its database (the history) | | `notapplicable`: fail2ban is not installed; `noaccess` |

`noaccess` comes only from a scan without root (the service runs as root). Without status.json the
verb answers every check `unconfigured` ("not checked yet"), with a broken one `failed`; neither has
a time or an item.

**Findings of `exposure`:** one per port at `info` or above that is not marked as expected. `fid`
is `port.<port>-<proto>`: never a text, a family, an address or the order, so it is the same in both
languages and on every scan. `state` is the port's; `title` the port as the item's detail names it
(`8080/tcp web`, the same in both languages, cut to 80 characters); `since` comes from `first_seen`
in the state (left out without it); `exposure` is `internet` when the whole internet reaches it in
one family, `restricted` when only some addresses do; `link` is `#/exposure/<port>-<proto>`, where
the page marks that port's row and brings it into view. A port that could not be assessed is no
finding: it makes the check `partial`. The most severe come first, at most 100 (the contract's limit
per answer), and `total` counts them all. `complete` is true only when the check `exposure` is
`checked` and every finding is listed. The item's own state and `value` stay as in the table above
(a marked port still counts there, as `info`).

`i18n.de.checks` holds the German titles and reasons of the checks. The verb checks the optional
parts as well (`secstatus.problems()`): a status.json that breaks them is unreadable.

## Page internals

- No build step, no framework, only `cockpit.js` from `../base1/`.
- Values from the system reach the page through `h()` and `textContent` only; translated texts may
  mark code with backticks (`rich()`), and a backtick in a value cannot open one (`tr()`).
  `test/files.test.js` refuses `innerHTML` and its relatives.
- Tabs: `exposure`, `ssh`, `logins`, `containers`, `crowdsec` and `fail2ban` (both only when
  installed). The location
  `#/<tab>` opens a tab, also while the page is open (`locationchanged`), as a link of the Status
  Board does; a tab chosen on the page goes into the location (`cockpit.location.go([tab])`).
- `#/exposure/<port>-<proto>`, the link of a finding, opens the exposure tab and marks that port's
  row (`aria-current="location"`, with the background a row has under the pointer) for as long as
  the location names it; once the rows are there and the page is shown, it unfolds the row's
  reasons and brings the row into view, once per link: a reload of the state does not scroll again.
  A link that arrives while the frame is hidden (`cockpit.hidden`) waits for `visibilitychange`. A
  port that is not there opens the tab only.
- Loading: `safeLoad()` never runs twice at once; the watch of status.json reloads only on a new tag.
- **Status in Cockpit's menu:** the entry "Security Monitor" carries Cockpit's own status icon for
  the host whose menu is shown: `danger` as `error`, `warning` as `warning`, `info` as `info`; `ok`
  and `none` show none. The tooltip is the summary of `status.json` in the session language (German
  from `i18n.de.summary`), cut to 200 characters (status contract, "Optional: a state in Cockpit's
  menu").
  - The page sends it with `cockpit.transport.control("notify", {page_status: {type, title}})`; the
    shell files it under the page of the frame that sends it and keeps it in
    `sessionStorage["cockpit:page_status"]`, so only the page behind the entry can set it.
    `"preload": ["index"]` in `manifest.json` makes the shell load the page right after the login,
    hidden.
  - `menu-status.js` watches `/var/lib/cockpit-security-monitor/status.json` (`cockpit.file`, no
    administrative access needed) and reads nothing else. It judges the status as the Status Board
    does: the worst of the document's state and the items' (`danger` > `warning` > `info`), and an
    item whose `checked_at` (with a zone) lies more than `stale_after` seconds (an hour) back makes
    it at least a warning, with "(as of <time>, out of date)" after the summary; it is checked again
    the moment the first item turns old. A missing or unreadable file shows no icon. A status is
    sent only when it changed, the first one always.
  - `security.js` waits for `SecurityMonitorMenuStatus.shown`, the first time `cockpit.hidden` is
    false, before it calls `security.py show`, checks by itself, watches status.json for reloads or
    reads the host name for the signature. The flag holds once the first answer about
    `status.json` is back (the shell's hint comes right after `init`, and its messages arrive in
    order); without any answer the page decides after 3 seconds. A link that arrives while the page
    is hidden selects its tab at once; a link to a port is brought into view once the page is shown
    and its rows are there.
- Version: `const VERSION` in `security.js`; `index.html` loads every file with `?v=<version>`;
  `tools/check-version.sh` keeps them and `CHANGELOG.md` in step.

## Tests

| File | Checks |
|---|---|
| `test/lib_test.py` | address classes, `ip -j addr`, every form of `ss` addresses, UFW's tuples, `sshd -T` and its assessment, authorized_keys (sizes and fingerprints equal to ssh-keygen's, options with quotes, DSA, garbage), accounts and key files, the journal (one failure per connection), cscli and the bouncer's YAML, the marks, Docker's allowed paths, fail2ban-client's `status` and `-d` (literals only, a jail only once added, the options that say where an action bans), port names and ranges, every code with its page text (fail2ban's findings and unread parts also with their status text) |
| `test/fw_test.py` | iptables-save and nft's JSON read into chains; UFW's default deny and allow rules, `ufw limit`, the IPv6 routing header rule, DOCKER-USER (new connections, the original port, one allowed network, ban lists), unknown matches both ways (also across chains), a part of the internet whose rule cannot be read, too many forks, queues, ipsets (as the source: a country list, an allow list, a ban list, against networks; as the destination), source ports (DHCP replies, a drop avoided, `--ports`), goto, two base chains, verdict maps, netdev ingress, samples |
| `test/scan_test.py` | every port of the hand-made scenarios and of the four derived ones with state and reason; Docker past UFW and docker-proxy for IPv6; addresses a socket is bound to; the addresses or the sockets not read (and, apart, a host really without a public address or a listening socket); the Hetzner Cloud Firewall (blocks, restricted, no token, stale, not matched, unreadable, rules not known, no incoming rule, several firewalls); SSH, logins, containers, CrowdSec; fail2ban (where each jail bans, the packet filter before the configuration, every finding, the bans now, not running, an unreadable database; on the scenario cut down to one jail: `-d`, `status`, `status JAIL` or ping failing, a configured jail not running, only the database missing; 31 jails, the last not asked); a DOCKER-USER rule (VPN only), no root, Docker failing (what it may publish not assessable, the rest as with its answer) or missing, legacy rules, an unreadable rule, an ipset as the source; the marks; `security-scan.py` writing both files, and twice in a row (`first_seen` taken over, a port gone in a complete check dropped); the state fixtures current; only documentation and private addresses in the fixtures |
| `test/status_test.py` | the status of every scenario in both languages: fields, ids, links, lengths, nothing private, no German in English; marks; unknown ports; an unreadable packet filter, addresses or sockets; Docker not answering; rules of a Hetzner Cloud Firewall not known; the fail2ban item (the warnings with their jail, else jails and bans; what could not be read, a jail not running, jails past the first 30, the history missing); an old state; the checks and findings: every scenario, the same `fid`s in English and German, with the ports in reverse order and on a second scan, a second dangerous port a second finding (the item stays danger), a marked port no finding, the packet filter, part of it, the addresses, the sockets, Docker, the Hetzner Cloud Firewall or a port not read making `exposure` partial and the list not complete, CrowdSec, fail2ban and Docker not installed (`notapplicable`) or not read, the journal, SSH, never checked and broken, more than 100 findings, `since`, a broken check or finding caught; `first_seen` kept, dropped when gone, kept after a partial check, garbage in it left out; `security.py status` (languages, the checks in German, wrong calls, missing, broken, unreadable, as a process within 2 seconds) |
| `test/verbs_test.py` | the arguments of `expect`/`unexpect`; writing the marks file, its copy, lines by hand kept, a file others can change refused, root required, German messages; the status after a mark (the port no finding, after the mark is removed a finding again with its first sighting) |
| `test/hetzner_test.py` | the server by IPv4 or IPv6 network, pages, no match, failures keeping the last good answer, the token never in the output, a firewall missing from the answer; how the scan reads rules (rules not known next to known ones, `[]`, the union of several firewalls) |
| `test/page.test.js` | the page in jsdom with the state fixtures: overview, ports and their reasons, every tab, links and keyboard, the summary without administrative access, the first check by itself, Refresh and its failures, the dialogs (timer, marks), page messages, escaping; the addresses or sockets not read; Docker not answering; rules of a Hetzner Cloud Firewall not known; the menu icon (every scenario's status in both languages, no file, a broken one, an item worse than the whole, out of date, the check again after an hour, what the board ignores), the page loaded hidden (nothing run, the first check only once shown), a link while the page is hidden; a link to a port (`#/exposure/<port>-<proto>`) in the open page, on opening and while hidden: its tab, the row marked and in view once, not again after a reload, the mark gone with a tab chosen, a port that is not there; the fail2ban tab (only when installed, findings, jails, bans, one hit and one ban in the singular, both languages, what could not be read, a jail not running, a jail not asked, only the history missing) |
| `test/i18n.test.js`, `test/files.test.js` | every text in both languages, no German in English, no long dash; no HTML from strings, nothing the CSP blocks, only the fixed verbs, the menu icon reading status.json only and sending only its page status, the manifest; every link of the status fixtures a place the page follows |
| `test/contrast_test.py`, `test/fonts_test.py` | WCAG contrast in light and dark; every font the page uses ships with it |
| `tools/check-units.sh` | `systemd-analyze verify`, and `systemd-analyze security` exposure at most 5.0 |
| `test/e2e/setup.sh`, `test/e2e_session.py` | CI (job `e2e`) on a throw-away runner: UFW on, Docker publishing 8080, fail2ban from Ubuntu with a jail on 8080 and one ban, a public address and a VPN as dummy interfaces; the page in a real Cockpit from the install with apt to the marks, a DOCKER-USER rule, the timer, a user without administrative access, the menu icon and links (also the link of the finding of 8080/tcp, which the status names with its checks); the steps are at the top of `test/e2e_session.py` |
| `test/e2e/upgrade.sh`, `test/e2e/board-rules.js`, `test/e2e/release-asset.sh` | CI (job `upgrade`) on a throw-away runner: the update from the release named in the workflow (`PREVIOUS_*`: 0.3.1, downloaded by `release-asset.sh`, which checks it against the SHA-256 pinned there and the release's `SHA256SUMS`). A public address on a dummy interface, UFW with 5432/tcp and 6379/tcp allowed and a listener on each; that release with its timer on, 6379/tcp marked and a scan (no `first_seen`, no checks or findings yet); then the package of this build with apt. `exposure.conf` and the timer stay; the scan the upgrade starts writes `first_seen` (that scan's time, for the marked port too) and a status with `features`, the six checks and 5432/tcp as a finding with that first sighting, 6379/tcp none; the status as nobody read by Status Board's own `src/lib/status.js` of its v0.3.0 (`board-rules.js`: readable, no item, check or finding left out); the next scan keeps the times; removing the package keeps `exposure.conf` and removes the state |
| `.github/workflows/e2e-suite.yml` | CI (workflow `e2e-suite`, on every pull request, every push to `main` and by hand): the shared suite of Host Settings (its reusable `suite.yml`, pinned by a full commit and passed as `suite` too) with this repository's commit as the candidate and Host Settings and Status Board from the released combination of that commit: real listeners on a public address behind UFW, the real scan, Host Settings' notifier against a real ntfy, Status Board in a real Cockpit; findings told once and resolved only by a complete check, a partial check, broken answers, no access. A pull request's candidate is its head commit; one that changes only text skips the suite and `e2e-suite / gate` still reports; the release requires the push run on the commit it releases. Details: `docs/INTERNALS.md` of Host Settings, "The shared suite (E2E-1)" |

Fixtures: `test/fixtures/<scenario>/` hold the outputs of the commands and files of a host; the text
outputs are written by hand after the formats of iptables 1.8.10, iproute2 6.x, OpenSSH 9.6 and ufw
0.36, the JSON parts by `test/fixtures/make_fixtures.py`, the SSH keys are real throw-away keys.
The scenario `fail2ban` is `ufw-docker` plus fail2ban 1.0.2 in the formats of its beautifier and
jail reader (four jails, one finding of each kind, `fail2ban-db.json` standing in for the
database); the job `e2e` checks the same against fail2ban as Ubuntu ships it and keeps its raw
answers in the artifact.
`test/fixtures/capture.sh` records a real host (to be made anonymous by hand; with `-` it prints
everything and keeps nothing, for a remote shell). The scenarios `derived-*` come from four real
servers recorded that way on 2026-10-20 (CI host, WireGuard edge, IPv6-only host, service host) and
depict none of them: public addresses in the documentation ranges, private addresses, ports, MACs
and link-local addresses replaced, container, image, network and path names neutral, most
containers left out with their networks, rules and sockets, personal comments and counters
removed; the journal, `/etc/passwd` and authorized_keys are not recorded (`meta.json` says so);
`test/fixtures/make_states.py` writes the `state-*.json` and `status-*.json` the page tests and the
preview read. The job `e2e` keeps the raw outputs of its runner in the artifact `e2e-session`.
