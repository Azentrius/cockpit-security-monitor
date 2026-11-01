#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# One file of a published release, for the upgrade tests (CI only): downloads FILE of the release
# TAG of the GitHub repository REPO into DIR, with the release's SHA256SUMS next to it, and stops
# unless the file has the SHA-256 the workflow pins and SHA256SUMS lists that same SHA-256 for it.
# The same file in every Azentrius add-on with an upgrade test.
#
#   sh test/e2e/release-asset.sh REPO TAG FILE SHA256 DIR
#   sh test/e2e/release-asset.sh Azentrius/cockpit-host-settings v0.1.0 cockpit-host-settings_0.1.0-1_all.deb 0449c2a2... previous
set -eu
repo=${1:?usage: release-asset.sh REPO TAG FILE SHA256 DIR}
tag=${2:?usage: release-asset.sh REPO TAG FILE SHA256 DIR}
file=${3:?usage: release-asset.sh REPO TAG FILE SHA256 DIR}
sum=${4:?usage: release-asset.sh REPO TAG FILE SHA256 DIR}
dir=${5:?usage: release-asset.sh REPO TAG FILE SHA256 DIR}
case $file in
    */*|SHA256SUMS|.*) echo "release-asset.sh: not a file of a release: $file" >&2; exit 64 ;;
esac
url=https://github.com/$repo/releases/download/$tag
mkdir -p "$dir"
for f in "$file" SHA256SUMS; do
    curl -fsSL --retry 3 --retry-all-errors --connect-timeout 20 --max-time 300 -o "$dir/$f" "$url/$f"
done
echo "$sum  $dir/$file" | sha256sum -c -
listed=$(awk -v f="$file" '$2 == f { print $1 }' "$dir/SHA256SUMS")
if [ "$listed" != "$sum" ]; then
    echo "release-asset.sh: SHA256SUMS of $repo $tag lists ${listed:-nothing} for $file, not the pinned $sum" >&2
    exit 1
fi
echo "$file of $repo $tag: SHA-256 as pinned and as in the release's SHA256SUMS"
