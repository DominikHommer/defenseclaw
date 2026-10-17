#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# Build the macOS package's portable e2fsprogs fallback from pinned source.
set -euo pipefail

if [ "$#" -ne 1 ] || [ "$(uname -s)" != Darwin ]; then
    echo "usage: build-macos-e2fsprogs.sh OUTPUT_DIR (macOS only)" >&2
    exit 2
fi
if [ "$(uname -m)" != arm64 ]; then
    echo "the managed macOS package needs an arm64 build Mac for e2fsprogs" >&2
    exit 1
fi
out=$1
export MACOSX_DEPLOYMENT_TARGET=13.0
version=1.47.3
sha=857e6ef800feaa2bb4578fbc810214be5d3c88b072ea53c5384733a965737329
url="https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${version}/e2fsprogs-${version}.tar.xz"
work=$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-e2fsprogs.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
curl --fail --location --silent --show-error --retry 3 "$url" -o "$work/source.tar.xz"
actual=$(shasum -a 256 "$work/source.tar.xz" | awk '{print $1}')
if [ "$actual" != "$sha" ]; then
    echo "e2fsprogs source checksum mismatch" >&2
    exit 1
fi
tar -xf "$work/source.tar.xz" -C "$work"
mkdir -p "$work/build" "$out/sbin" "$out/licenses"
(
    cd "$work/build"
    "$work/e2fsprogs-$version/configure" --disable-nls --enable-libuuid --enable-libblkid --disable-rpath
    make -j "$(sysctl -n hw.ncpu)"
)
for row in misc/mke2fs debugfs/debugfs e2fsck/e2fsck; do
    tool=${row##*/}
    install -m 0755 "$work/build/$row" "$out/sbin/$tool"
    # The recipient must not need Homebrew or a build-machine keg at runtime.
    if otool -L "$out/sbin/$tool" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)' >/dev/null; then
        echo "$tool has a non-system runtime library dependency" >&2
        exit 1
    fi
done
install -m 0644 "$work/e2fsprogs-$version/NOTICE" "$out/licenses/NOTICE"
install -m 0644 "$work/source.tar.xz" "$out/licenses/e2fsprogs-$version.tar.xz"
printf 'e2fsprogs %s\nSource: %s\nSHA-256: %s\nLicense terms: NOTICE; complete corresponding source: e2fsprogs-%s.tar.xz\n' \
    "$version" "$url" "$sha" "$version" >"$out/licenses/README.txt"
