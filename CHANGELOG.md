# Changelog

## Unreleased

What could not be read is never OK, also when Docker does not answer or fail2ban runs many jails.

- **Docker not answering:** with Docker's socket there but no answer from its API, no published
  port was known, so the docker-proxy socket of a port Docker forwards past UFW was judged by UFW's
  input chain: "not reachable" instead of open. A socket of docker-proxy, or one on a port a DNAT
  rule names, is now "Not assessable" from the internet, the VPN and the private network (reason
  `no-docker`); this host is judged as before. A port whose VPN or private network reach is not
  known is never "this host only". The overview says Docker could not be asked, and the status item
  `exposure` starts with it and is "not checked" unless a port found is at least a note.
- **More than 30 fail2ban jails:** only the first 30 are asked for their state, and the others
  counted as OK without an answer. They are now "not checked" (`skipped`), fail2ban is incomplete
  (`skipped` in `incomplete`), and the tab and the status item say how many were not asked.
- Tests for both, with their counterparts: Docker answering, 30 jails.
- **Menu:** the entry moves to the end of System, after Services, in one block with the other
  Azentrius add-ons (Status Board, Security Monitor, Update Gaps, Image Update Monitor, Cron Jobs,
  Host Settings). Searching the menu for "azentrius" finds them all, and Cockpit's Help menu links
  the README.

## 0.3.1 – 2026-10-23

What could not be read is never OK.

- **Addresses or sockets not read:** when `ip -j addr` fails, every port not bound to the loopback
  is "Not assessable" from the internet, the VPN and the private network (it was "this host
  only"), and "no public address" becomes "not known" (`network.public` `null`). When `ss` fails,
  only the ports Docker publishes are listed and the page says so. The status item `exposure` is
  then "not checked" unless a port found is at least a note, and its detail names what could not be
  read instead of "no port reachable". A host that really has no public address or no listening
  socket stays OK.
- **Hetzner Cloud Firewall whose rules are not known:** a firewall applied to the server but
  missing from the API's answer (`rules` null) was read as having no rules, so it blocked every
  port. It now counts as no protection: the port is judged as without a Hetzner answer ("only rules
  outside this host could protect it" when the host does not filter), unless a known rule lets the
  whole internet in anyway. A known empty rule list still blocks everything, and the rules of
  several firewalls are joined as Hetzner does. The overview names such a firewall.
- **fail2ban not read completely:** a failed `fail2ban-client -d`, `status` or `status JAIL`, or no
  answer to `ping` while the service is active, made the assessment OK. Now fail2ban and the jails
  concerned are "not checked" (`incomplete` in the state) unless a finding is at least a note; the
  tab says what failed and why, the status item starts with it. Without fail2ban's database only
  the history is missing: a note on the tab and at the end of the status detail, the state stands.
- **A jail that does not run:** a jail in the configuration that fail2ban's list of running jails
  lacks is a warning (`jail-not-running`), on the tab and in the status. A jail is OK only when it
  runs and answered.
- Tests for each case and its counterpart (a real empty answer, an empty Hetzner rule list,
  several firewalls, only the history missing, a jail running).

## 0.3.0 – 2026-10-22

fail2ban, shown: what it watches, whom it bans, and where a ban does not take effect.

- **A tab fail2ban** when fail2ban is installed: the service, every jail with what it reads (files
  or journal), where its ban takes effect (the chain or hook the packet filter has, else the
  action's options), ports and protocols, its counters since the start (one hit, one ban in the
  singular) and its rules; the bans now and the history of 14 days from fail2ban's database,
  opened read-only. The page changes nothing in fail2ban.
- **Where a ban fails:** fail2ban installed but not running; a ban only at INPUT or the hook input
  (Ubuntu's default `nftables` action) in front of a port Docker publishes to the internet does
  not reach the container (warning; a note for an all-ports ban); TCP only while the port is open
  for UDP too (HTTP/3); a log missing or unchanged for 3 days; not one hit since fail2ban started
  more than a day ago although the log is not empty.
- **Bans fail2ban does not manage:** addresses in fail2ban's chains or sets that fail2ban does not
  hold as banned (they never expire), and `f2b-` chains in a saved ruleset such as
  `/etc/iptables/rules.v4`.
- **Status item `fail2ban`** for the Status Board, only when installed: the bans now, the warnings
  with their jail, no addresses.
- **Package and docs:** the package description and the AppStream data (Cockpit's Applications
  page) name fail2ban; the README says which systems are tested how and how a release is made;
  `docs/INTERNALS.md` describes every field of `fail2ban` in the state.
- Tests: a scenario with four jails and each finding, the parsers of `fail2ban-client status` and
  `-d`, and in the end-to-end job fail2ban as Ubuntu ships it with a jail in front of Docker's port.

## 0.2.0 – 2026-10-21

Findings from the first real scan of a server, said more precisely.

- **The rule that keeps everyone else out:** a port reachable only from some sources names, first,
  the rule or policy that stops the rest (a country list in DOCKER-USER, `! -s NET -j DROP`, the
  policy), not only the rule that lets the allowed sources in (`limited_by` in the state).
- **Locked accounts whose keys still log in:** `passwd -l` closes only the password; with
  `UsePAM yes` sshd does not check the lock. An account locked that way (a `!` in front of a real
  hash in `/etc/shadow`, read as root) that still has keys is a warning, and the page names
  `usermod --expiredate 1` as the way to close it. Not for root, an expired account, or sshd
  without PAM; accounts that never had a password (`!`, `*`) are key-only by design.
- **Ports only some addresses reach, counted apart:** the figure of the status item `exposure` and
  the page's overview count the ports the whole internet reaches; a port open only to a country
  list or an allowed network is named apart ("only from some addresses").
- **The journal's real start:** when the journal begins later than 14 days back (rotation), the
  status says since when instead of "in 14 days", and the logins tab says where the journal
  begins (`journalctl --lines=+1`, systemd 254 or newer).

## 0.1.0 – 2026-10-21

First version: what is reachable from where on a server, who logs in, and what
weakens the boundary of its containers. Read only.

- **Exposure:** every listening socket and every port Docker publishes, reachable from the internet,
  the VPN, the private network or only the host, for IPv4 and IPv6, with the rule or policy that
  decides. The packet filter comes from `iptables-save` and `ip6tables-save` (UFW's and Docker's
  tables) and `nft -j list ruleset` (every other table); Docker's port mappings and their DNAT
  show where UFW does not apply. Rules the page cannot read make a port "Not assessable", never
  "OK". An ipset of sources (a country list) makes a port "reachable only from" that set; a source
  port is the sender's choice. Databases, Docker's API, Cockpit and SSH open to the internet are a
  danger, web, WireGuard and the DHCP client a note, everything else a warning until marked as
  expected.
- **Hetzner Cloud Firewall:** read with a read-only token by a service of its own without root
  (`cockpit-security-hetzner.service`, the token through `LoadCredential=`); a port it blocks is OK,
  a failing API keeps the last good answer and says how old it is.
- **SSH and logins:** the effective configuration (`sshd -T`), the authorized_keys of every account
  with a login shell (type, size, fingerprint, options, who can change the file), the logins of the
  last 14 days from the journal (sshd, sshd-session, sudo, cockpit-session); a login from outside
  the VPN and private networks is a warning.
- **Containers:** the Docker socket, privileged, host PIDs, extra capabilities, writable host
  folders, the host network, root, no-new-privileges, AppArmor.
- **CrowdSec:** shown when installed: the service, its version, bouncers, active decisions, alerts
  of 14 days, sharing; an outdated engine and a bouncer that does not protect container ports are
  warnings.
- **Mark as expected:** a port or a container finding, with a note, in
  `/etc/cockpit-security-monitor/exposure.conf`; the only change the page makes besides its timer.
- **Status for the Status Board:** `security.py status --lang en|de` (status contract, schema 1)
  with the items `exposure`, `ssh`, `logins`, `containers`, `crowdsec` and `scan`.
- **The page:** Azentrius page frame, tabs with links (`#/exposure`, `#/ssh`, …), English and
  German, light and dark, phones; without administrative access the summary only.
- **In Cockpit's menu:** the entry carries the add-on's state as Cockpit's own status icon, judged
  as the Status Board judges `status.json` (an item older than an hour at least a warning), with
  the summary as its tooltip. Cockpit loads the page hidden after the login for it
  (`"preload": ["index"]`); the page calls its helper and checks by itself only once it is shown.
- Tests against hand-made scenarios of real formats and four real servers recorded read only and
  made anonymous (`test/fixtures/capture.sh`), the page under jsdom, and an end-to-end test in CI
  with a real Cockpit, UFW and Docker.
