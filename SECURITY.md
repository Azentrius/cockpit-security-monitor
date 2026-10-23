# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report them privately through GitHub instead:
[Report a vulnerability](https://github.com/Azentrius/cockpit-security-monitor/security/advisories/new)
(tab **Security → Report a vulnerability** in this repository).
If you cannot use GitHub, write to **support@azentrius.com**.

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

To stay on a supported version, upgrade to the newest release:

```bash
# From packages.azentrius.com (Debian, Ubuntu; see README)
sudo apt update && sudo apt install cockpit-security-monitor

# From the files of the release: check the download first, then install it
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify <file> --repo Azentrius/cockpit-security-monitor
sudo apt install ./cockpit-security-monitor_X.Y.Z-1_all.deb
```

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
- data from the system (rule texts, container, process and jail names, key comments, log paths)
  that reaches the page as markup or script (the Cockpit session can act as root),
- the scan reaching the network other than through the loopback, or calling Docker with anything
  but GET,
- the scan changing anything in fail2ban (it runs only `fail2ban-client --version`, `ping`,
  `status` and `-d`) or in fail2ban's database (opened read-only), or log lines from that
  database reaching the state,
- the Hetzner token reaching anything but `cockpit-security-hetzner.service` (the browser, the
  state files, the journal),
- a port shown as not reachable that is reachable (a wrong "OK" is the worst finding this add-on
  can make), or a fail2ban ban shown as reaching a port it does not reach,
- `/etc/cockpit-security-monitor/exposure.conf` being accepted when others than root can write it,
  or "Mark as expected" writing anything else,
- the package `cockpit-security-monitor` (its install and removal scripts) or `make install`
  overwriting or exposing files it should not touch.
