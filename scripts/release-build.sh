#!/usr/bin/env bash
# Builds the release binaries (darwin/arm64, linux/amd64) into dist/ under the
# toolchain go.mod pins, then builds them again from a copy of the tree in a
# fresh directory with an empty build cache, and fails unless each pair is
# byte-identical. dist/SHA256SUMS lists the binaries.
#
#   VERSION=v0.1.0 scripts/release-build.sh   # VERSION defaults to git describe
set -euo pipefail
cd "$(dirname "$0")/.."

version=${VERSION:-$(git describe --tags --always --dirty)}
toolchain=$(sed -n 's/^toolchain //p' go.mod)
export GOTOOLCHAIN=$toolchain CGO_ENABLED=0 GOFLAGS=-mod=readonly
platforms="darwin/arm64 linux/amd64"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

build() { # <source dir> <output dir>
	local p
	for p in $platforms; do
		(cd "$1" && GOOS=${p%/*} GOARCH=${p#*/} go build -trimpath -buildvcs=false \
			-ldflags="-buildid= -X main.version=$version" \
			-o "$2/peer-$version-${p%/*}-${p#*/}" ./cmd/peer)
	done
}

rm -rf dist
mkdir -p dist
build "$PWD" "$PWD/dist"

fresh=$(mktemp -d)
trap 'chmod -R u+w "$fresh"; rm -rf "$fresh"' EXIT
mkdir "$fresh/src" "$fresh/dist"
tar --exclude=./.git --exclude=./dist -cf - . | tar -C "$fresh/src" -xf -
GOCACHE="$fresh/cache" build "$fresh/src" "$fresh/dist"

status=0
for f in dist/peer-*; do
	a=$(sha256 "$f" | cut -d' ' -f1)
	b=$(sha256 "$fresh/dist/${f#dist/}" | cut -d' ' -f1)
	if [ "$a" = "$b" ]; then
		echo "reproducible ${f#dist/} $a"
	else
		echo "DIFFERS ${f#dist/} $a $b" >&2
		status=1
	fi
done
(cd dist && sha256 peer-* >SHA256SUMS)
exit $status
