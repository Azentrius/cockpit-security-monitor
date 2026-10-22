# Contributing

Bug reports, ideas and pull requests for Security Monitor are welcome. Security problems do not
belong in public issues: report them as described in [SECURITY.md](SECURITY.md). For a larger
change, open an issue first so we can agree on the approach.

## Setup

```bash
git clone https://github.com/Azentrius/cockpit-security-monitor.git
cd cockpit-security-monitor
(cd test && npm ci)                    # jsdom for the page tests
pip install -r test/requirements.txt   # pinned check tools: shellcheck, ruff, playwright
```

- The helpers need **Python ≥ 3.8, standard library only**. `ruff` checks Python 3.8 syntax.
- The page is plain JavaScript without a build step.
- Node.js and npm (CI uses Node 22) are needed for the tests only.

## Tests and checks

```bash
make check                       # every offline test: helpers against the scenarios, page under jsdom, design, version
make lint                        # shellcheck, ruff, systemd-analyze for the units, as in CI
make packages                    # .deb and .rpm in dist/ (needs dpkg-deb and rpmbuild)
python3 tools/preview/build.py   # the page with test data: tools/preview/out/security/index.html?scenario=ufw-docker
```

The offline tests need no root and no network: the helpers read the scenarios in `test/fixtures/`
through `test/fakesys.py`. A new case of the packet filter goes into `test/fw_test.py` (a few
iptables-save lines are enough) or, when it needs a whole host, into a new scenario. The `test`
workflow runs the lint, the tests and the package build on every push and pull request; the job
`python-min` runs the helper tests on Python 3.8, and the job `e2e` runs the page in a real
Cockpit with UFW, Docker and fail2ban.

## How the add-on is built

- **Read only.** The helpers list and never change a firewall rule, never restart anything, and
  change nothing in CrowdSec or fail2ban. Docker is asked with GET only, fail2ban's database is
  opened read-only. The page changes only the add-on's own timer and marks file, and both go
  through a dialog: show → confirm → live output → result.
- **Root code only in `lib/`**, installed to `/usr/lib/cockpit-security-monitor` (root-owned).
  Nothing is ever run or imported from a directory others can write.
- **Root without the network.** The scan allows only the loopback. The Hetzner request runs as a
  user of its own and is the only part that sees the token.
- **Fixed verbs.** The page calls `security.py` only with fixed verbs; every argument is checked
  there. New verbs go into `docs/INTERNALS.md`.
- **Honest results.** What the page does not understand is "Not assessable", never "OK"; every tab
  says what it does not check.
- **Formats are contracts.** `state.json`, `status.json`, the marks file and the verbs' JSON change
  together with the page, the fixtures, the tests and `docs/INTERNALS.md`.
- **No build step, no runtime dependencies.** Python standard library, POSIX `sh`, JavaScript without
  a framework. `node_modules` is for the tests only.
- **Browser without network.** No CDNs, external fonts or images; Cockpit's strict CSP stays.
- **Shared design files** (`plugin/azentrius.*`, `plugin/icons.js`, the fonts) are byte-identical
  copies from other Azentrius add-ons, pinned in `tools/design-files.sha256`. Do not edit them here.

## Requirements for a change

- **English and German.** Every user-facing text goes into both languages of `plugin/i18n.js`; the
  status texts into both of `lib/secstatus.py`; the messages of `security.py` through `say(de, en)`.
  German addresses the user formally ("Sie"). The tests check that the English page contains no
  German.
- **English in the repository.** Code, comments, docs, commit messages and pull requests are in
  English; the only German is the translation and the tests that check it.
- **Tests** for new behaviour; `make check` and `make lint` green.
- **SPDX header** `SPDX-License-Identifier: Apache-2.0` in every new source file.
- **No private data.** No secrets, tokens, host names, public addresses other than the documentation
  ranges, user names or other real server data in issues, pull requests, tests or fixtures.

## Pull requests

- Open them against `main`. `main` is protected: every change goes through a pull request and is
  squash-merged once the checks are green.
- The title becomes the commit on `main`: short, imperative, English, without a version number.
- Keep one topic per pull request and fill in the template: what and why, how it was tested.

## License

Security Monitor is licensed under the [Apache License 2.0](LICENSE); contributions are accepted under
the same license. Third-party material keeps its own license and is listed in [NOTICE](NOTICE).
