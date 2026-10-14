#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

set -eu
repo=$(unset CDPATH; cd -- "$(dirname -- "$0")/../../.." && pwd)
build=$repo/scripts/build-macos-enterprise-pkg.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Extract the function that the generated postinstall receives. This runs on
# Linux with an isolated payload; no package or macOS host is needed.
awk '/^refresh_signed_launchagent_binary\(\) \{/ { copying=1 } copying { print } copying && /^}/ { exit }' "$build" >"$work/replace.sh"
grep -q '^refresh_signed_launchagent_binary() {' "$work/replace.sh"
awk '/^cat >"\$SCRIPTS\/postinstall" <<'\''EOF'\''$/ { copying=1; next } copying && /^EOF$/ { exit } copying { print }' "$build" >"$work/postinstall"
shellcheck "$work/postinstall"
refresh_line=$(grep -n '^if ! refresh_signed_launchagent_binary ' "$build" | head -n 1 | cut -d: -f1)
ensure_line=$(grep -n 'enterprise macos ensure --from-package' "$build" | tail -n 1 | cut -d: -f1)
[ -n "$refresh_line" ] && [ -n "$ensure_line" ] && [ "$refresh_line" -lt "$ensure_line" ]

binary=$work/defenseclaw-gateway
other=$work/other-product
printf '%s\n' 'signed gateway bytes' >"$binary"
printf '%s\n' 'unrelated bytes' >"$other"
chmod 0755 "$binary"
before=$(stat -c '%d:%i' "$binary")
owner=$(stat -c '%u:%g' "$binary")
sh -c '. "$1"; refresh_signed_launchagent_binary "$2"' sh "$work/replace.sh" "$binary"
first=$(stat -c '%d:%i' "$binary")
[ "$before" != "$first" ]
[ "$(stat -c '%a' "$binary")" = 755 ]
[ "$(stat -c '%u:%g' "$binary")" = "$owner" ]
[ "$(cat "$binary")" = 'signed gateway bytes' ]
sh -c '. "$1"; refresh_signed_launchagent_binary "$2"' sh "$work/replace.sh" "$binary"
second=$(stat -c '%d:%i' "$binary")
[ "$first" != "$second" ]
[ "$(cat "$other")" = 'unrelated bytes' ]
ln -s "$binary" "$work/gateway-link"
if sh -c '. "$1"; refresh_signed_launchagent_binary "$2"' sh "$work/replace.sh" "$work/gateway-link"; then
    echo 'postinstall accepted a symlink as the signed binary' >&2
    exit 1
fi
[ -L "$work/gateway-link" ]

mkdir "$work/fakebin"
printf '#!/bin/sh\nexit 1\n' >"$work/fakebin/mv"
chmod 0755 "$work/fakebin/mv"
if PATH="$work/fakebin:$PATH" sh -c '. "$1"; refresh_signed_launchagent_binary "$2"' sh "$work/replace.sh" "$binary"; then
    echo 'a failed rename appeared to succeed' >&2
    exit 1
fi
[ "$(stat -c '%d:%i' "$binary")" = "$second" ]
[ "$(cat "$binary")" = 'signed gateway bytes' ]
if find "$work" -maxdepth 1 -name '.defenseclaw-gateway.pkg.*' | grep -q .; then
    echo 'a postinstall temporary file remains' >&2
    exit 1
fi
echo 'macOS pkg postinstall binary replacement: PASS'
