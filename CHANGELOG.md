# Changelog

## 0.1.0 – 2026-10-20

First version (not released yet): what is reachable from where on a server, who logs in, and what
weakens the boundary of its containers. Read only.

- **Exposure:** every listening socket and every port Docker publishes, reachable from the internet,
  the VPN, the private network or only the host, for IPv4 and IPv6, with the rule or policy that
  decides. The packet filter comes from `iptables-save` and `ip6tables-save` (UFW's and Docker's
  tables) and `nft -j list ruleset` (every other table); Docker's port mappings and their DNAT
  show where UFW does not apply. Rules the page cannot read make a port "Not assessable", never
  "OK". An ipset of sources (a country list) makes a port "reachable only from" that set; a port
  reachable only from some sources names the rule that keeps everyone else out; a source port is
  the sender's choice. Databases, Docker's API, Cockpit and SSH open to the internet are a
  danger, web, WireGuard and the DHCP client a note, everything else a warning until marked as
  expected.
- **Hetzner Cloud Firewall:** read with a read-only token by a service of its own without root
  (`cockpit-security-hetzner.service`, the token through `LoadCredential=`); a port it blocks is OK,
  a failing API keeps the last good answer and says how old it is.
- **SSH and logins:** the effective configuration (`sshd -T`), the authorized_keys of every account
  with a login shell (type, size, fingerprint, options, who can change the file), the logins of the
  last 14 days from the journal (sshd, sshd-session, sudo, cockpit-session); a login from outside
  the VPN and private networks is a warning. An account locked with `passwd -l` whose keys still
  log in is a warning: with `UsePAM yes` sshd does not check the lock, and the page names
  `usermod --expiredate 1` as the way to close it. When the journal begins later than 14 days
  back, the page and the status say since when instead of "14 days".
- **Containers:** the Docker socket, privileged, host PIDs, extra capabilities, writable host
  folders, the host network, root, no-new-privileges, AppArmor.
- **CrowdSec:** shown when installed: the service, its version, bouncers, active decisions, alerts
  of 14 days, sharing; an outdated engine and a bouncer that does not protect container ports are
  warnings.
- **Mark as expected:** a port or a container finding, with a note, in
  `/etc/cockpit-security-monitor/exposure.conf`; the only change the page makes besides its timer.
- **Status for the Status Board:** `security.py status --lang en|de` (status contract, schema 1)
  with the items `exposure`, `ssh`, `logins`, `containers`, `crowdsec` and `scan`. The figure of
  `exposure` counts the ports the whole internet reaches; ports only some addresses reach are
  named apart, here and in the page's overview.
- **The page:** Azentrius page frame, tabs with links (`#/exposure`, `#/ssh`, …), English and
  German, light and dark, phones; without administrative access the summary only.
- **In Cockpit's menu:** the entry carries the add-on's state as Cockpit's own status icon, judged
  as the Status Board judges `status.json` (an item older than an hour at least a warning), with
  the summary as its tooltip. Cockpit loads the page hidden after the login for it
  (`"preload": ["index"]`); the page calls its helper and checks by itself only once it is shown.
- Tests against hand-made scenarios of real formats and four real servers recorded read only and
  made anonymous (`test/fixtures/capture.sh`), the page under jsdom, and an end-to-end test in CI
  with a real Cockpit, UFW and Docker.
