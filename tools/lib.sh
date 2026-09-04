#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# lib.sh -- the two things every script in tools/ was doing its own copy of:
# deciding a scratch directory is safe to write into and to DELETE, and building
# the throwaway XDG_DESKTOP_PORTAL_DIR the development frontend reads.
#
# Sourced, never executed.

# --------------------------------------------------------------- scratch dirs
#
# WHAT THESE DIRECTORIES HOLD, and why the check is not paranoia: a SoftHSM
# fixture directory contains the PKCS#11 module path the BACKEND dlopen()s, and
# a portal directory decides which .portal files the frontend reads and which
# backend it therefore hands a card session to. Both are `rm -rf`ed by these
# scripts.
#
# THE OLD CHECK WAS OWNERSHIP ONLY, and ownership is not enough for an `rm -rf`:
# a mistyped SOFTHSM_DIR or LOGDIR pointing at $HOME passes it. So a directory
# these scripts will write into or remove must ALSO be
#
#   * under $TMPDIR (or /tmp), by real path, so a variable pointing at a home
#     directory or a source tree is refused rather than emptied; and
#   * carrying THIS project's marker file naming the fixture that created it,
#     so a directory that exists but was made by something else is refused
#     rather than reused.
#
# A directory that does not exist yet is created and claimed. One that exists
# without a marker is never touched: the message says to remove it by hand,
# because a script guessing that an unmarked directory is disposable is exactly
# the accident the marker exists to prevent.

XDP_FIXTURE_MARKER=".xdg-desktop-portal-certificate-fixture"

lib_die() {
	echo "${0##*/}: $*" >&2
	exit 40
}

# The real path of $TMPDIR, without a trailing slash.
fixture_tmp_root() {
	local root="${TMPDIR:-/tmp}"

	root="$(realpath -m -- "$root")" || lib_die "could not resolve TMPDIR '$root'"
	printf '%s' "${root%/}"
}

# fixture_under_tmp PATH -- true when PATH's real path is strictly inside it.
fixture_under_tmp() {
	local path real root

	path="$1"
	root="$(fixture_tmp_root)"
	real="$(realpath -m -- "$path")" || return 1

	case "$real" in
	"$root"/?*) return 0 ;;
	*) return 1 ;;
	esac
}

# fixture_claim DIR TAG -- write the marker. The directory must already exist
# and must have been created by this script.
fixture_claim() {
	local dir="$1" tag="$2"

	printf '%s\n' "$tag" >"$dir/$XDP_FIXTURE_MARKER" ||
		lib_die "could not write the fixture marker in $dir"
}

# fixture_check DIR TAG -- refuse anything this project did not make.
#
# Repairs the one thing that can be repaired (a mode that is too open on a
# directory we own) and refuses everything else, because the alternatives are
# writing a module path into somebody else's directory or deleting one.
fixture_check() {
	local dir="$1" tag="$2" owner mode claimed

	[ -L "$dir" ] && lib_die "$dir is a symlink; refusing to use it"
	[ -d "$dir" ] || lib_die "$dir exists and is not a directory"

	fixture_under_tmp "$dir" ||
		lib_die "$dir is not under ${TMPDIR:-/tmp}; these fixtures are only ever created,
and only ever removed, inside the temporary directory. Set TMPDIR if you want
them somewhere else."

	owner="$(stat -c %u "$dir")"
	[ "$owner" = "$(id -u)" ] || lib_die "$dir is owned by uid $owner, not $(id -u)"

	if [ ! -f "$dir/$XDP_FIXTURE_MARKER" ]; then
		lib_die "$dir has no $XDP_FIXTURE_MARKER and was not created by this project.
Refusing to write into it or remove it. If it IS disposable, remove it by hand:
    rm -rf -- '$dir'"
	fi

	claimed="$(cat "$dir/$XDP_FIXTURE_MARKER" 2>/dev/null)"
	[ "$claimed" = "$tag" ] ||
		lib_die "$dir belongs to the '$claimed' fixture, not '$tag'; refusing to reuse it"

	mode="$(stat -c %a "$dir")"
	case "$mode" in
	700 | 500) ;;
	*)
		echo "${0##*/}: tightening $dir from mode $mode to 700" >&2
		chmod 700 "$dir" || lib_die "could not chmod $dir"
		;;
	esac
}

# fixture_make DIR TAG -- create it if it is not there, then check it.
fixture_make() {
	local dir="$1" tag="$2"

	fixture_under_tmp "$dir" ||
		lib_die "$dir is not under ${TMPDIR:-/tmp}; refusing to create a fixture there"

	if [ ! -e "$dir" ]; then
		(umask 077 && mkdir -p "$dir") || lib_die "could not create $dir"
		fixture_claim "$dir" "$tag"
	fi

	fixture_check "$dir" "$tag"
}

# fixture_remove DIR TAG -- the only `rm -rf` in this project's tools.
fixture_remove() {
	local dir="$1" tag="$2"

	[ -e "$dir" ] || return 0
	fixture_check "$dir" "$tag"
	rm -rf -- "$dir"
}

# fixture_mktemp PREFIX TAG -- a fresh directory with an unguessable name,
# already claimed. Echoes the path.
fixture_mktemp() {
	local prefix="$1" tag="$2" dir

	dir="$(mktemp -d "${TMPDIR:-/tmp}/$prefix.XXXXXXXX")" || lib_die "mktemp failed"
	fixture_claim "$dir" "$tag"
	printf '%s' "$dir"
}

# --------------------------------------------------- the dev XDG_DESKTOP_PORTAL_DIR
#
# THE WHOLE MACHINE'S PORTALS, PLUS OURS. Setting XDG_DESKTOP_PORTAL_DIR makes
# the frontend ignore EVERY other .portal directory and EVERY other portals.conf
# on the machine (desktop-portal/xdp-portal-config.c: both lookups `goto out` /
# return as soon as the variable is set). A directory holding only
# certificate.portal therefore does not mean "our backend plus the usual ones";
# it means our backend and NOTHING ELSE -- no file chooser, no screenshot, and
# no SETTINGS.
#
# That was a real bug and it had two visible faces:
#
#   * the chooser and the PIN prompt came up in the light theme on a dark
#     desktop, because org.freedesktop.portal.Settings had no backend to answer
#     org.freedesktop.appearance/color-scheme from; and
#   * in --live mode the stack took org.freedesktop.portal.Desktop on the REAL
#     session bus with that configuration, so for as long as it ran EVERY
#     portal on the session was gone, not just replaced.
#
# So the directory is populated with a symlink to every .portal the machine has,
# and the portals.conf is a COPY of the machine's effective one with a single
# line added for this backend. What that buys is a development stack that
# differs from the session in exactly one respect, which is the only kind of
# development stack a bug can be trusted to reproduce in.

# xdp_data_dirs -- $XDG_DATA_HOME then $XDG_DATA_DIRS, in the frontend's order.
xdp_data_dirs() {
	local dirs

	printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}"
	dirs="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
	printf '%s\n' "$dirs" | tr ':' '\n'
}

# xdp_desktops -- $XDG_CURRENT_DESKTOP lower-cased, one per line. The frontend
# looks for <desktop>-portals.conf in that order before portals.conf.
xdp_desktops() {
	printf '%s\n' "${XDG_CURRENT_DESKTOP:-}" | tr ':' '\n' | tr '[:upper:]' '[:lower:]' |
		grep -v '^$'
}

# xdp_effective_conf -- the portals.conf the machine would use, in the
# frontend's own search order. Echoes a path, or nothing.
xdp_effective_conf() {
	local dir desktop

	for dir in "${XDG_CONFIG_HOME:-$HOME/.config}/xdg-desktop-portal" \
		$(printf '%s\n' "${XDG_CONFIG_DIRS:-/etc/xdg}" | tr ':' '\n' | sed 's:$:/xdg-desktop-portal:') \
		/etc/xdg-desktop-portal \
		$(xdp_data_dirs | sed 's:$:/xdg-desktop-portal:'); do
		while read -r desktop; do
			[ -f "$dir/$desktop-portals.conf" ] && {
				printf '%s' "$dir/$desktop-portals.conf"
				return 0
			}
		done < <(xdp_desktops)

		[ -f "$dir/portals.conf" ] && {
			printf '%s' "$dir/portals.conf"
			return 0
		}
	done

	return 1
}

# xdp_write_portal_dir DIR REPO -- fill DIR with every .portal on the machine,
# this repository's certificate.portal, and a merged portals.conf.
xdp_write_portal_dir() {
	local dir="$1" repo="$2" source_dir base found conf

	for source_dir in $(xdp_data_dirs | sed 's:$:/xdg-desktop-portal/portals:'); do
		[ -d "$source_dir" ] || continue

		for found in "$source_dir"/*.portal; do
			[ -f "$found" ] || continue
			base="$(basename "$found")"
			# First one wins, which is the frontend's own rule.
			[ -e "$dir/$base" ] && continue
			ln -s -- "$found" "$dir/$base"
		done
	done

	# OURS IS A REAL FILE AND IT OVERWRITES: an installed certificate.portal
	# from a previous `ninja install` must not shadow the one being tested.
	# The comments are stripped so the file is readable in the log; the
	# installed one keeps them.
	rm -f -- "$dir/certificate.portal"
	sed -e '/^#/d' -e '/^$/d' "$repo/data/certificate.portal.in" >"$dir/certificate.portal"

	# THE MACHINE'S OWN CONFIGURATION, PLUS ONE LINE. Written as plain
	# portals.conf rather than <desktop>-portals.conf because that name is the
	# frontend's fallback and is read whatever XDG_CURRENT_DESKTOP says.
	conf="$(xdp_effective_conf)" || conf=""

	if [ -n "$conf" ]; then
		cp -- "$conf" "$dir/portals.conf"
		echo "${0##*/}: portals.conf copied from $conf" >&2
	else
		printf '[preferred]\ndefault=none;\n' >"$dir/portals.conf"
		echo "${0##*/}: no portals.conf on this machine; starting from default=none" >&2
	fi

	# Named explicitly rather than through default=, so that the log line the
	# frontend prints names the interface this backend implements. Inserted
	# inside [preferred]; a config without that section gets one.
	if grep -q '^\[preferred\]' "$dir/portals.conf"; then
		sed -i '0,/^\[preferred\]/s//[preferred]\norg.freedesktop.impl.portal.experimental.Certificate=certificate;/' \
			"$dir/portals.conf"
	else
		printf '\n[preferred]\norg.freedesktop.impl.portal.experimental.Certificate=certificate;\n' \
			>>"$dir/portals.conf"
	fi
}

# ------------------------------------------------------------ waiting for a name
#
# WAIT FOR THE NAME, DO NOT SLEEP AND HOPE. Loading the PKCS#11 modules takes a
# couple of seconds on a machine with several configured, and a fixed sleep
# raced it: the frontend's first call came back "was not provided by any
# .service files", there being no activation file on a private bus.
#
# xdp_wait_for_name NAME PID -- poll for at most 30 seconds, giving up early if
# the process that is meant to own it has exited.
xdp_wait_for_name() {
	local name="$1" pid="$2" owned=""

	for _ in $(seq 1 120); do
		owned="$(gdbus call --session --dest org.freedesktop.DBus \
			--object-path /org/freedesktop/DBus \
			--method org.freedesktop.DBus.NameHasOwner "$name" 2>/dev/null)"
		case "$owned" in
		*true*) return 0 ;;
		esac

		kill -0 "$pid" 2>/dev/null || return 1
		sleep 0.25
	done

	return 1
}
