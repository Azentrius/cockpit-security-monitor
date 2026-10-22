#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Prepares a throw-away machine for test/e2e_session.py (CI, test workflow, job e2e; never a
# machine you use), as spec 4.7 asks:
#   - two Cockpit users with the passwords given: ADMIN_USER in the sudo group, PLAIN_USER not,
#   - a public address and a VPN as dummy interfaces (pub0 203.0.113.10/24, wg0 10.8.0.1/24),
#     the classes the page sorts sources into,
#   - UFW on: incoming denied, everything from the VPN allowed,
#   - Docker publishing a port on 0.0.0.0 (sm-web, 8080 -> 80), which Docker forwards past UFW,
#   - fail2ban from Ubuntu with a jail e2e-web on 8080 (default nftables action: hook input) and
#     one banned address.
# All output goes to stderr.
#
#   sudo env ADMIN_USER=… ADMIN_PW=… PLAIN_USER=… PLAIN_PW=… sh test/e2e/setup.sh
set -eu
: "${ADMIN_USER:?}" "${ADMIN_PW:?}" "${PLAIN_USER:?}" "${PLAIN_PW:?}"
export DEBIAN_FRONTEND=noninteractive
exec 1>&2
# apt-get with a time limit and retries (a stuck mirror must not hold the job)
APT_GET="$(cd "$(dirname "$0")/../.." && pwd)/tools/apt-get.sh"

# The GitHub runner image sets XDG_CONFIG_HOME=/home/runner/.config for everyone in
# /etc/environment: Cockpit's bridge, started for another user, then fails on the runner's
# config folder and the login ends with 401. The test users get their own.
if grep -q '^XDG_CONFIG_HOME=' /etc/environment 2> /dev/null; then
    sed -i '/^XDG_CONFIG_HOME=/d' /etc/environment
fi
useradd -m -s /bin/bash -G sudo "$ADMIN_USER"
useradd -m -s /bin/bash "$PLAIN_USER"
printf '%s:%s\n%s:%s\n' "$ADMIN_USER" "$ADMIN_PW" "$PLAIN_USER" "$PLAIN_PW" | chpasswd

ip link add pub0 type dummy
ip addr add 203.0.113.10/24 dev pub0
ip link set pub0 up
ip link add wg0 type dummy
ip addr add 10.8.0.1/24 dev wg0
ip link set wg0 up

command -v ufw > /dev/null || sh "$APT_GET" install ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on wg0 comment VPN
ufw --force enable
ufw status verbose

docker run -d --name sm-web -p 8080:80 nginx:1.27-alpine
for _ in $(seq 30); do
    if curl -fsS -o /dev/null http://127.0.0.1:8080/; then break; fi
    sleep 1
done
docker ps
ip -br addr

# fail2ban as Ubuntu ships it (banaction nftables: a chain at the hook input) with a jail in front
# of Docker's 8080, which that ban never reaches, and one address banned in it.
sh "$APT_GET" install fail2ban python3-systemd
printf '%s\n' '203.0.113.99 - - [20/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12' > /var/log/e2e-web.log
cat > /etc/fail2ban/jail.d/e2e.local <<'EOF'
[e2e-web]
enabled = true
filter = nginx-http-auth
port = 8080
logpath = /var/log/e2e-web.log
EOF
systemctl restart fail2ban
for _ in $(seq 30); do
    if fail2ban-client ping > /dev/null 2>&1 && fail2ban-client status e2e-web > /dev/null 2>&1; then break; fi
    sleep 1
done
fail2ban-client set e2e-web banip 192.0.2.77
fail2ban-client status
fail2ban-client status e2e-web
nft list table inet f2b-table || true
