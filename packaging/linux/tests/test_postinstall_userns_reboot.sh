#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/systemd"
cat >"$work/bin/systemctl" <<'MOCK'
#!/bin/sh
[ "$1" != is-active ]
MOCK
cat >"$work/bin/defenseclaw-gateway" <<'MOCK'
#!/bin/sh
cat <<'JSON'
{"ok":false,"installed":true,"installed_version":"1.0.4","action":"ensure","errors":[{"code":"unprivileged_user_namespaces","message":"reboot this host"}]}
JSON
exit 1
MOCK
for command in systemd-sysusers systemd-tmpfiles sync; do
    printf '#!/bin/sh\nexit 0\n' >"$work/bin/$command"
done
chmod +x "$work/bin/"*
sed -e "s#/run/systemd/system#$work/systemd#g" \
    -e "s#/opt/defenseclaw/bin/defenseclaw-gateway#$work/bin/defenseclaw-gateway#g" \
    -e "s#/var/lib/defenseclaw-enterprise#$work/state#g" \
    -e "s#/run/defenseclaw-enterprise-apply-path.held#$work/held#g" \
    packaging/linux/postinstall.sh >"$work/postinstall.sh"
PATH="$work/bin:$PATH" sh "$work/postinstall.sh" configure >"$work/stdout" 2>"$work/stderr"
if ! grep -q 'until this host reboots' "$work/stderr"; then
    cat "$work/stderr" >&2
    exit 1
fi
if grep -q 'not applied\|no deployment is active' "$work/stderr"; then
    echo 'postinstall claimed an applied deployment was not applied' >&2
    exit 1
fi
test -s "$work/state/last-package-result.json"
