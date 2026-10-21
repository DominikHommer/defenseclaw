#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise deb: apt Pre-Install-Pkgs hook that refuses to
# downgrade the package before dpkg runs, so the running deployment is left
# alone. The older release may not read the current config, so its services
# could fail to start. A package script cannot do
# this: dpkg runs the installed package's prerm with the incoming version,
# but when it fails dpkg falls back to the incoming package's own prerm and
# unpacks the older files anyway. rpm has no such hook, and a plain
# `dpkg -i` does not run apt hooks, so only an apt install is covered; there
# the incoming package's preinstall checks (a release before 1.0.4 checks
# neither the marker nor the bundle release floor).
#
# apt sends the "VERSION 2" protocol on stdin (see apt.conf(5)): the
# configuration, a blank line, then one line per package action:
#   name old-version direction new-version action
# A deliberate rollback creates the root-owned marker first. The hook leaves
# it in place: the older package's preinstall checks it as well, and its
# postinstall applies the package with --allow-downgrade and deletes it.

set -u
state=/var/lib/defenseclaw-enterprise
gateway=/opt/defenseclaw/bin/defenseclaw-gateway
config=/etc/defenseclaw/config.yaml
previous_config=/etc/defenseclaw/config.yaml.v8.bak

change=$(awk 'body && $1 == "defenseclaw-enterprise" && $3 == ">" && $4 != "-" { print $2, $4; exit } $0 == "" { body = 1 }')
[ -n "$change" ] || exit 0
# shellcheck disable=SC2086 # two version strings without blanks
set -- $change
installed=$1
incoming=$2

# The product version of a deb version: no epoch, and the prerelease back
# behind "-" (the deb writes 1.0.4-rc.1 as 1.0.4~rc.1). A prerelease is older
# than its release: dropping it let 1.0.4 go to 1.0.4~SNAPSHOT unrefused.
product() { printf '%s' "$1" | sed -e 's/^[0-9]*://' -e 's/~/-/'; }
# not_older A B: A is not older than B, by the lifecycle's version order (the
# package preinstall's not_older; enterpriseunix compareProductVersions).
not_older() {
    awk -v a="$1" -v b="$2" '
        function norm(v) { sub(/^v/, "", v); sub(/\+.*/, "", v); return v }
        BEGIN {
            a = norm(a); b = norm(b); pa = ""; pb = ""
            if (index(a, "-")) { pa = substr(a, index(a, "-") + 1); a = substr(a, 1, index(a, "-") - 1) }
            if (index(b, "-")) { pb = substr(b, index(b, "-") + 1); b = substr(b, 1, index(b, "-") - 1) }
            na = split(a, x, "."); nb = split(b, y, "."); n = na > nb ? na : nb
            for (i = 1; i <= n; i++) {
                xi = (i <= na) ? x[i] + 0 : 0; yi = (i <= nb) ? y[i] + 0 : 0
                if (xi > yi) exit 0
                if (xi < yi) exit 1
            }
            if (pa == pb || pa == "") exit 0
            if (pb == "") exit 1
            np = split(pa, u, "."); nq = split(pb, w, "."); m = np > nq ? np : nq
            for (i = 1; i <= m; i++) {
                if (u[i] == w[i]) continue
                if (u[i] ~ /^[0-9]+$/ && w[i] ~ /^[0-9]+$/) exit (u[i] + 0 > w[i] + 0) ? 0 : 1
                exit (u[i] > w[i]) ? 0 : 1
            }
            exit 0
        }'
}
to=$(product "$incoming")
not_older "$to" "$(product "$installed")" && exit 0

# The rollback marker does not lift the release floor of a confirmed signed
# policy bundle (min_product_version); exit 3 is the gateway's refusal.
if [ -x "$gateway" ]; then
    floor_msg=$("$gateway" enterprise bundle floor-check --product-version "$to" 2>&1 >/dev/null)
    if [ $? -eq 3 ]; then
        echo "defenseclaw-enterprise: refusing to downgrade to $incoming: ${floor_msg#Error: } Nothing was changed." >&2
        exit 1
    fi
fi

marker=$state/allow-downgrade
if [ -f "$marker" ] && [ ! -L "$marker" ]; then
    # Leave the marker: the older package's preinstall checks it too, and its
    # postinstall applies the package with --allow-downgrade and deletes it.
    exit 0
fi
echo "defenseclaw-enterprise: $installed is installed; refusing to downgrade to $incoming. The older release may not read the current config. Nothing was changed." >&2
echo "  For a deliberate rollback create the marker first: sudo touch $marker" >&2
if [ -f "$previous_config" ]; then
    config=$previous_config
fi
echo "  Then install the older package; its postinstall applies it." >&2
echo "  If it refuses the config, run: sudo $gateway enterprise linux ensure --from-package --allow-downgrade --config $config" >&2
exit 1
