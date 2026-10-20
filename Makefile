# Security Monitor, a Cockpit add-on: what is reachable from where, who logs in, what is blocked
# SPDX-License-Identifier: Apache-2.0
#
# The paths are fixed (the page, the helpers and the units refer to each other by them);
# DESTDIR only stages. The usual way to install is the package (make packages).

DESTDIR ?=
PAGE = $(DESTDIR)/usr/share/cockpit/security
HELPERS = $(DESTDIR)/usr/lib/cockpit-security-monitor
UNITS = $(DESTDIR)/usr/lib/systemd/system
CONF = $(DESTDIR)/etc/cockpit-security-monitor
VERSION := $(shell sed -n 's/^ *const VERSION = "\(.*\)";.*/\1/p' plugin/security.js)
# Reproducible archives and packages: file times from the last commit.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)

.PHONY: all install uninstall check lint dist stage packages preview

all:
	@echo "Nothing to build. Try: make check, make lint, make packages, sudo make install"

install:
	install -d $(PAGE) $(HELPERS) $(UNITS)
	install -d -m 755 $(CONF)
	install -m 644 plugin/* $(PAGE)/
	install -m 755 lib/security-scan.py lib/security.py lib/security-hetzner.py $(HELPERS)/
	install -m 644 lib/seclib.py lib/secfw.py lib/seccheck.py lib/secstatus.py lib/secproc.py $(HELPERS)/
	install -m 644 systemd/*.service systemd/*.timer $(UNITS)/
	if [ -z "$(DESTDIR)" ]; then sh packaging/scripts/configure; fi

uninstall:
	sh packaging/scripts/remove
	rm -rf $(PAGE) $(HELPERS)
	rm -f $(UNITS)/cockpit-security-scan.service $(UNITS)/cockpit-security-scan.timer \
		$(UNITS)/cockpit-security-hetzner.service
	sh packaging/scripts/removed

# Every offline test (helpers against the scenarios, the page under jsdom, design, version).
check:
	cd test && npm ci && bash run-all.sh

# As in CI (the tools: pip install -r test/requirements.txt).
lint:
	shellcheck --severity=warning tools/*.sh test/*.sh test/e2e/*.sh test/fixtures/*.sh packaging/scripts/*
	ruff check .
	sh tools/check-units.sh

# Source archive of the last commit.
dist:
	git archive --format=tar.gz --prefix=cockpit-security-monitor-$(VERSION)/ \
		-o cockpit-security-monitor-$(VERSION).tar.gz HEAD
	@echo cockpit-security-monitor-$(VERSION).tar.gz

# The files of the .deb and .rpm, as installed, in build/root.
stage:
	rm -rf build/root
	$(MAKE) install DESTDIR=build/root
	install -D -m 644 packaging/de.azentrius.security_monitor.metainfo.xml \
		build/root/usr/share/metainfo/de.azentrius.security_monitor.metainfo.xml
	install -D -m 644 NOTICE build/root/usr/share/doc/cockpit-security-monitor/copyright
	install -m 644 LICENSE build/root/usr/share/doc/cockpit-security-monitor/LICENSE
	install -m 644 plugin/CC-BY-4.0-Font-Awesome.txt build/root/usr/share/doc/cockpit-security-monitor/

# cockpit-security-monitor_VERSION-1_all.deb and cockpit-security-monitor-VERSION-1.noarch.rpm in
# dist/ (needs dpkg-deb and rpmbuild), reproducible.
packages: stage
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) sh tools/build-packages.sh build/root $(VERSION) dist

# The page with the scenarios' data: tools/preview/out/security/index.html?scenario=ufw-docker
preview:
	python3 tools/preview/build.py
