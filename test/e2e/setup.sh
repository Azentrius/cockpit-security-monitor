#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Prepares a throw-away machine for test/e2e_session.py (CI, test workflow, job e2e; never a
# machine you use), as spec 4.7 asks:
#   - two Cockpit users with the passwords given: ADMIN_USER in the sudo group, PLAIN_USER not,
#   - a public address and a VPN as dummy interfaces (pub0 203.0.113.10/24, wg0 10.8.0.1/24),
#     the classes the page sorts sources into,
#   - UFW on: incoming denied, everything from the VPN allowed,
#   - Docker publishing a port on 0.0.0.0 (sm-web, 8080 -> 80), which Docker forwards past UFW.
# All output goes to stderr.
#
#   sudo env ADMIN_USER=… ADMIN_PW=… PLAIN_USER=… PLAIN_PW=… sh test/e2e/setup.sh
set -eu
: "${ADMIN_USER:?}" "${ADMIN_PW:?}" "${PLAIN_USER:?}" "${PLAIN_PW:?}"
export DEBIAN_FRONTEND=noninteractive
exec 1>&2

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

command -v ufw > /dev/null || apt-get install -y -qq ufw > /dev/null
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on wg0 comment VPN
ufw --force enable
ufw status verbose

docker run -d --name sm-web -p 8080:80 nginx:1.27-alpine
for i in $(seq 30); do
    if curl -fsS -o /dev/null http://127.0.0.1:8080/; then break; fi
    sleep 1
done
docker ps
ip -br addr
