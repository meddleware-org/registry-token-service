#!/bin/sh
# Writes the licence texts of everything compiled into the token-service binary: the third-party Go modules
# the build graph of ./cmd/server pulls in, and the Go standard library. The Dockerfile runs this in the
# builder stage and ships the result in the image (/usr/share/doc/registry-token-service/); go-ci.yml runs
# it too, so a module without a licence file fails the build instead of shipping without a notice.
#
#   scripts/third-party-licenses.sh OUTPUT_FILE
#
# Run from the repository root with the modules downloaded (`go mod download`).
set -eu

out=${1:?usage: third-party-licenses.sh OUTPUT_FILE}

# Path, version and directory of every non-main module the binary is built from (sorted, unique).
mods=$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/server | sort -u)
[ -n "$mods" ] || { echo "no third-party modules found; run from the repository root" >&2; exit 1; }

# Licence and notice files of a directory (top level only), one path per line.
notice_files() {
	find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | sort
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
	echo "Third-party software compiled into the registry-token-service binary."
	echo "The service itself is licensed under the 0BSD licence (see LICENSE)."
	echo
	echo "$mods" | while read -r path version dir; do
		files=$(notice_files "$dir")
		if [ -z "$files" ]; then
			echo "no licence file found for $path $version" >&2
			exit 1
		fi
		echo "================================================================================"
		echo "$path $version"
		echo "================================================================================"
		echo
		echo "$files" | while read -r f; do
			cat "$f"
			echo
		done
	done
	goroot=$(go env GOROOT)
	echo "================================================================================"
	echo "Go standard library $(go env GOVERSION)"
	echo "================================================================================"
	echo
	cat "$goroot/LICENSE"
} > "$tmp"

# The file must name every module it covers, and carry real licence text.
echo "$mods" | while read -r path _; do
	grep -q "^$path " "$tmp" || { echo "$path missing from the notices" >&2; exit 1; }
done
[ "$(wc -c < "$tmp")" -gt 2000 ] || { echo "notices file is implausibly short" >&2; exit 1; }

cp "$tmp" "$out"
echo "wrote $out: $(echo "$mods" | wc -l) third-party modules plus the Go standard library"
