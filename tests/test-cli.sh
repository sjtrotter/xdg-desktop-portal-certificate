#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>

set -u

BACKEND="$1"
GCR="$2"
failures=0
checks=0

expect_output() {
	local what="$1" want_status="$2" want_output="$3"
	shift 3
	local output status

	output="$("$BACKEND" "$@" 2>&1)"
	status=$?
	checks=$((checks + 1))
	if [ "$status" -eq "$want_status" ] && [[ "$output" == $want_output ]]; then
		echo "ok $checks - $what"
	else
		failures=$((failures + 1))
		echo "not ok $checks - $what"
		printf '#   status: %s\n' "$status"
		printf '%s\n' "$output" | sed 's/^/#   /'
	fi
}

VERSION='xdg-desktop-portal-certificate * (impl interface version *, experimental)'
expect_output "help lists pin-prompt" 0 '*--pin-prompt=WHICH*' --help

for kind in gtk auto; do
	expect_output "$kind accepts an equals argument" 0 "$VERSION" --pin-prompt="$kind" --version
	expect_output "$kind accepts a separate argument" 0 "$VERSION" --pin-prompt "$kind" --version
done

if [ "$GCR" = no-gcr ]; then
	ERROR='xdg-desktop-portal-certificate: --pin-prompt=system requires a build with gcr-4'
	expect_output "system requires gcr" 64 "$ERROR" --pin-prompt=system
	expect_output "system requires gcr with version" 64 "$ERROR" --pin-prompt=system --version
	expect_output "system requires gcr with a separate argument" 64 "$ERROR" --pin-prompt system
	expect_output "system matching is case insensitive" 64 "$ERROR" --pin-prompt=SYSTEM
else
	expect_output "system accepts version with gcr" 0 "$VERSION" --pin-prompt=system --version
fi

echo "1..$checks"
[ "$failures" -eq 0 ] || exit 1
