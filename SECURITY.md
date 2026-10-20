# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report them privately through GitHub instead:
[Report a vulnerability](https://github.com/Azentrius/cockpit-security-monitor/security/advisories/new)
(tab **Security → Report a vulnerability** in this repository).
If you cannot use GitHub, write to **support@azentrius.de**.

Please include:

- what is affected (page, helper script, systemd unit or package; version or commit),
- steps to reproduce,
- the impact you expect.

Do not send real credentials, tokens, passwords or other private data from your servers. Redact logs,
rule sets and command output before you attach them (host names, IP addresses, user names, API
tokens); a made-up example is just as good.

We aim to acknowledge reports within 7 days. This is a small project, so a fix may take longer; we
will keep you informed and credit you in the advisory unless you prefer to stay anonymous. Please keep
the details private until a fixed release is out.

## Supported versions

| Version | Security fixes |
|---|---|
| Newest release | yes |
| Older releases | no |

The add-on is in its 0.x line: only the newest release is supported. Security fixes go into a new
patch or minor release of the latest release line; older releases get no backports. The `main` branch
is a development state, not a supported installation.

## How fixes are announced

A fixed vulnerability is announced with:

- a GitHub security advisory in this repository (tab **Security**), with a CVE ID where one is assigned,
- an entry in `CHANGELOG.md` marked as a security fix,
- the release notes of the fixed release, which come from `CHANGELOG.md`.

## Especially relevant

The helpers in `lib/` run as root, from Cockpit and from the add-on's systemd service, and one of
them holds an API token. Reports are particularly welcome for:

- ways to make the page run commands or arguments other than the fixed verbs of `security.py`,
- anything that makes the root helpers run or import code from a directory others can write,
- data from the system (rule texts, container and process names, key comments, log lines) that
  reaches the page as markup or script (the Cockpit session can act as root),
- the scan reaching the network other than through the loopback, or calling Docker with anything
  but GET,
- the Hetzner token reaching anything but `cockpit-security-hetzner.service` (the browser, the
  state files, the journal),
- a port shown as not reachable that is reachable (a wrong "OK" is the worst finding this add-on
  can make),
- `/etc/cockpit-security-monitor/exposure.conf` being accepted when others than root can write it,
  or "Mark as expected" writing anything else,
- the package `cockpit-security-monitor` (its install and removal scripts) or `make install`
  overwriting or exposing files it should not touch.
