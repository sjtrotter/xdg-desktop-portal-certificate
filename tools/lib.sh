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
# WHAT THESE DIRECTORIES HOLD, and why the checks are not paranoia: a SoftHSM
# fixture directory contains the PKCS#11 module path the BACKEND dlopen()s, and
# a portal directory decides which .portal files the frontend reads and which
# backend it therefore hands a card session to. Both are removed by these
# scripts.
#
# THE FIVE THINGS THAT ARE CHECKED, and each is here because ownership alone is
# not enough for a recursive delete:
#
#   1. NO SYMLINKS ON THE PATH. The path is compared against its own resolved
#      real path, so a fixture reached through a link -- which is how a
#      directory that passes every other check can still be somebody else's --
#      is refused rather than followed.
#   2. UNDER $TMPDIR, by real path, so a mistyped variable pointing at a home
#      directory or a source tree is refused rather than emptied.
#   3. EVERY ANCESTOR from $TMPDIR down is owned by this user or by root, and
#      is not writable by anyone else unless it is sticky -- which is exactly
#      what /tmp is. Without this a fixture can be correct and still be reached
#      through a directory a second user can rename underneath it.
#   4. A MARKER that is a REGULAR FILE, owned by this user, mode 0600, naming
#      the fixture that created it. A marker that is a symlink, or one another
#      user could have written, proves nothing.
#   5. MODE 0700 (or 0500) ON THE FIXTURE ITSELF, and it is REFUSED rather than
#      repaired. Every fixture here is created exclusively with umask 077, so
#      it is 0700 from its first instant; one that is not 0700 now was open at
#      some point, and a directory that was writable is a directory whose
#      marker may have been forged.
#
# A directory that does not exist is created exclusively -- mktemp -d for the
# throwaway ones, a plain mkdir (never mkdir -p, which is happy to adopt a
# directory somebody else has just made) for the one whose name two other
# scripts have to be able to predict. One that exists without a valid marker is
# never touched: the message says to remove it by hand, because a script
# guessing that an unmarked directory is disposable is exactly the accident the
# marker exists to prevent.
#
# $TMPDIR ITSELF IS THE OPERATOR'S CHOICE and is not validated beyond 3 above.
# Containment under it is a guard against a typo, not a trust boundary: a
# TMPDIR pointing somewhere unwise is a decision the person running these
# scripts made, and what the checks defend is the case where somebody ELSE
# controls part of the path.

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

# fixture_no_symlinks PATH -- true when no component of PATH is a symlink.
# Compares the lexically normalised path with the fully resolved one.
fixture_no_symlinks() {
	local path="$1" lexical real

	lexical="$(realpath -m -s -- "$path")" || return 1
	real="$(realpath -e -- "$path" 2>/dev/null)" || return 1
	[ "$lexical" = "$real" ]
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

# fixture_dir_safe PATH -- an ancestor we are willing to reach a fixture
# through: owned by us or by root, and not writable by anyone else unless it is
# sticky.
fixture_dir_safe() {
	local path="$1" owner mode sticky group other

	owner="$(stat -c %u -- "$path" 2>/dev/null)" || return 1
	[ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ] || return 1

	mode="$(stat -c %04a -- "$path" 2>/dev/null)" || return 1
	sticky=$((0${mode:0:1} & 1))
	group=$((0${mode:2:1} & 2))
	other=$((0${mode:3:1} & 2))

	if [ "$group" -ne 0 ] || [ "$other" -ne 0 ]; then
		[ "$sticky" -eq 1 ] || return 1
	fi

	return 0
}

# fixture_ancestors_ok REAL -- $TMPDIR, and every directory between it and
# REAL's parent.
fixture_ancestors_ok() {
	local real="$1" root path

	root="$(fixture_tmp_root)"
	fixture_dir_safe "$root" ||
		lib_die "$root is not owned by this user or root, or is writable by others without
the sticky bit; refusing to keep fixtures under it"

	path="$(dirname -- "$real")"
	while [ "$path" != "$root" ] && [ "$path" != "/" ]; do
		fixture_dir_safe "$path" ||
			lib_die "$path is on the path to a fixture and is not owned by this user or
root, or is writable by others without the sticky bit; refusing to use it"
		path="$(dirname -- "$path")"
	done
}

# fixture_claim DIR TAG -- write the marker. The directory must have just been
# created by this script.
fixture_claim() {
	local dir="$1" tag="$2"

	(umask 177 && printf '%s\n' "$tag" >"$dir/$XDP_FIXTURE_MARKER") ||
		lib_die "could not write the fixture marker in $dir"
	chmod 600 "$dir/$XDP_FIXTURE_MARKER" || lib_die "could not chmod the marker in $dir"
}

# fixture_refuse REAL REASON -- every refusal names the manual way out, because
# fixture_remove refuses the same directories fixture_check does and a script
# that will neither use nor delete a directory has to say what will.
fixture_refuse() {
	lib_die "$2
Refusing to write into it or remove it. If it IS disposable, remove it by hand:
    rm -rf -- '$1'"
}

# fixture_check DIR TAG -- refuse anything this project did not make.
fixture_check() {
	local dir="$1" tag="$2" real marker owner mode claimed kind

	[ -L "$dir" ] && lib_die "$dir is a symlink; refusing to use it"
	[ -d "$dir" ] || lib_die "$dir exists and is not a directory"

	fixture_no_symlinks "$dir" ||
		lib_die "$dir is reached through a symlink; refusing to use it"

	fixture_under_tmp "$dir" ||
		lib_die "$dir is not under ${TMPDIR:-/tmp}; these fixtures are only ever created,
and only ever removed, inside the temporary directory. Set TMPDIR if you want
them somewhere else."

	real="$(realpath -e -- "$dir")" || lib_die "could not resolve $dir"
	fixture_ancestors_ok "$real"

	owner="$(stat -c %u -- "$real")"
	[ "$owner" = "$(id -u)" ] ||
		fixture_refuse "$real" "$real is owned by uid $owner, not $(id -u)."

	marker="$real/$XDP_FIXTURE_MARKER"

	[ -L "$marker" ] &&
		fixture_refuse "$real" "$real has a symlink where its fixture marker should be."
	kind="$(stat -c %F -- "$marker" 2>/dev/null)" || kind=""
	[ "$kind" = "regular file" ] ||
		fixture_refuse "$real" "$real has no $XDP_FIXTURE_MARKER and was not created by this project."

	owner="$(stat -c %u -- "$marker")"
	[ "$owner" = "$(id -u)" ] ||
		fixture_refuse "$real" "the fixture marker in $real is owned by uid $owner."

	mode="$(stat -c %a -- "$marker")"
	[ "$mode" = "600" ] ||
		fixture_refuse "$real" "the fixture marker in $real is mode $mode, not 600.
A fixture made before this check existed has a 0644 marker; re-create it with the
script that owns it (tools/softhsm-fixture.sh for the SoftHSM one) or:
    chmod 600 -- '$marker'"

	claimed="$(cat -- "$marker" 2>/dev/null)"
	[ "$claimed" = "$tag" ] ||
		fixture_refuse "$real" "$real belongs to the '$claimed' fixture, not '$tag'."

	mode="$(stat -c %a -- "$real")"
	case "$mode" in
	700 | 500) ;;
	*)
		fixture_refuse "$real" "$real is mode $mode, not 700.
Fixtures are created 0700 and stay 0700; one that is not was open at some point
and its marker cannot be trusted."
		;;
	esac
}

# fixture_create DIR TAG -- create it exclusively and claim it. mkdir, never
# mkdir -p: mkdir fails if the directory already exists, so this cannot adopt
# one somebody else created a moment ago, and umask 077 means it is never
# briefly readable by anyone else.
fixture_create() {
	local dir="$1" tag="$2"

	fixture_under_tmp "$dir" ||
		lib_die "$dir is not under ${TMPDIR:-/tmp}; refusing to create a fixture there"

	(umask 077 && mkdir -- "$dir") || lib_die "could not create $dir"
	fixture_claim "$dir" "$tag"
}

# fixture_make DIR TAG -- create it if it is not there, then check it.
fixture_make() {
	local dir="$1" tag="$2"

	[ -e "$dir" ] || [ -L "$dir" ] || fixture_create "$dir" "$tag"
	fixture_check "$dir" "$tag"
}

# fixture_remove DIR TAG -- the only recursive delete in this project's tools.
# It runs on the RESOLVED path, after fixture_check has passed on it, and
# --one-file-system stops it descending into anything that has been mounted
# inside the fixture since it was made.
fixture_remove() {
	local dir="$1" tag="$2" real

	[ -e "$dir" ] || [ -L "$dir" ] || return 0
	fixture_check "$dir" "$tag"

	real="$(realpath -e -- "$dir")" || lib_die "could not resolve $dir"
	rm -rf --one-file-system -- "$real" || lib_die "could not remove $real"
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
# and the portals.conf is the machine's EFFECTIVE configuration flattened into
# one file, with one line replaced for this backend.

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

# xdp_config_chain -- EVERY portals.conf the frontend would load, in its order,
# one path per line.
#
# THE FRONTEND DOES NOT STOP AT THE FIRST FILE, which is what the old helper
# assumed. desktop-portal/xdp-portal-config.c loads one configuration per
# directory in the chain (load_portal_configurations()) and then resolves EACH
# INTERFACE against the whole list (xdp_portal_config_find()): the first
# configuration that names the interface, or that has a `default`, decides it,
# and a `none` anywhere in that configuration's list for the interface means no
# backend at all. So copying the first file loses whatever a later one said --
# a partial ~/.config file hiding /etc's `Screenshot=none`, for instance.
#
# Within a directory the frontend takes <desktop>-portals.conf for the first
# matching $XDG_CURRENT_DESKTOP entry, and portals.conf only if none matched.
xdp_config_chain() {
	local dir desktop found

	for dir in "${XDG_CONFIG_HOME:-$HOME/.config}/xdg-desktop-portal" \
		$(printf '%s\n' "${XDG_CONFIG_DIRS:-/etc/xdg}" | tr ':' '\n' | sed 's:$:/xdg-desktop-portal:') \
		/etc/xdg-desktop-portal \
		$(xdp_data_dirs | sed 's:$:/xdg-desktop-portal:') \
		/usr/share/xdg-desktop-portal; do
		found=""

		while read -r desktop; do
			if [ -f "$dir/$desktop-portals.conf" ]; then
				found="$dir/$desktop-portals.conf"
				break
			fi
		done < <(xdp_desktops)

		[ -z "$found" ] && [ -f "$dir/portals.conf" ] && found="$dir/portals.conf"
		[ -n "$found" ] && printf '%s\n' "$found"
	done | awk '!seen[$0]++'
}

# xdp_flatten_preferred FILE... -- the chain's EFFECTIVE [preferred] map as one
# section.
#
# For each interface named anywhere in the chain, and for `default`, this walks
# the chain in order and builds the candidate list the frontend would try:
#
#   * a configuration that lists `none` for the interface ends the list there
#     (portal_config_interface_prefers_none() returns before anything else);
#   * a configuration that names the interface contributes its list, then its
#     own `default` list, because that is the order
#     xdp_portal_config_find() tries them in within one configuration;
#   * a configuration that does not name it contributes its `default` list, and
#     a `none` there ends the list for the same reason.
#
# The result is fed back to the frontend as one file, where the same
# "first installed candidate wins" rule reaches the same answer.
xdp_flatten_preferred() {
	[ $# -gt 0 ] || return 0

	awk '
	function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
	function has_none(s,   n, a, i) {
		n = split(s, a, ";")
		for (i = 1; i <= n; i++) if (trim(a[i]) == "none") return 1
		return 0
	}
	function add(item) {
		if (item == "" || item == "none" || (item in used)) return
		used[item] = 1
		out = (out == "" ? item : out ";" item)
	}
	function addlist(s,   n, a, i) {
		n = split(s, a, ";")
		for (i = 1; i <= n; i++) add(trim(a[i]))
	}
	function terminate() { out = (out == "" ? "none" : out ";none"); return out }
	function flatten(key,   i, il, dl) {
		delete used
		out = ""
		for (i = 1; i <= nf; i++) {
			il = ((i SUBSEP key) in vals) ? vals[i, key] : NOKEY
			dl = ((i SUBSEP "default") in vals) ? vals[i, "default"] : NOKEY
			if (il != NOKEY) {
				if (has_none(il)) return terminate()
				addlist(il)
				if (dl != NOKEY) addlist(dl)
			} else if (dl != NOKEY) {
				if (has_none(dl)) return terminate()
				addlist(dl)
			}
		}
		return out
	}
	BEGIN { NOKEY = "\001none-such\001"; nf = 0; nk = 0 }
	FNR == 1 { nf++; section = "" }
	{
		line = trim($0)
		if (line ~ /^[#;]/ || line == "") next
		if (line ~ /^\[.*\]$/) { section = substr(line, 2, length(line) - 2); next }
		if (section != "preferred") next
		eq = index(line, "=")
		if (eq == 0) next
		key = trim(substr(line, 1, eq - 1))
		if (!(key in seen)) { seen[key] = 1; allkeys[++nk] = key }
		vals[nf, key] = trim(substr(line, eq + 1))
	}
	END {
		print "[preferred]"
		for (i = 1; i <= nk; i++) {
			if (allkeys[i] == "default") continue
			r = flatten(allkeys[i])
			if (r != "") printf "%s=%s;\n", allkeys[i], r
		}
		r = flatten("default")
		if (r != "") printf "default=%s;\n", r
	}
	' "$@"
}

# xdp_conf_set FILE KEY VALUE -- replace KEY's line, or add it. The generated
# file has exactly one section and it is [preferred], so appending is enough;
# inserting a key BEFORE an existing one would not override it, which is what
# the old helper did.
xdp_conf_set() {
	local file="$1" key="$2" value="$3" tmp="$1.tmp"

	awk -v k="$key" 'index($0, k "=") != 1' "$file" >"$tmp" || lib_die "could not rewrite $file"
	printf '%s=%s\n' "$key" "$value" >>"$tmp"
	mv -f -- "$tmp" "$file" || lib_die "could not replace $file"
}

# xdp_write_portal_dir DIR REPO [MODE] -- fill DIR with every .portal on the
# machine, this repository's certificate.portal, and the flattened portals.conf.
# MODE is "private" (the default) or "live".
xdp_write_portal_dir() {
	local dir="$1" repo="$2" mode="${3:-private}" source_dir base found
	local chain=()

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

	# Written as plain portals.conf rather than <desktop>-portals.conf because
	# that name is the frontend's fallback and is read whatever
	# XDG_CURRENT_DESKTOP says.
	mapfile -t chain < <(xdp_config_chain)

	if [ "${#chain[@]}" -gt 0 ]; then
		xdp_flatten_preferred "${chain[@]}" >"$dir/portals.conf"
		echo "${0##*/}: portals.conf flattened from ${#chain[@]} file(s)" >&2
		printf '%s: chain %s\n' "${0##*/}" "${chain[@]}" >&2
	else
		printf '[preferred]\ndefault=none;\n' >"$dir/portals.conf"
		echo "${0##*/}: no portals.conf on this machine; default=none" >&2
	fi

	# Named explicitly rather than through default=, so that the frontend's log
	# line names the interface this backend implements.
	xdp_conf_set "$dir/portals.conf" \
		org.freedesktop.impl.portal.experimental.Certificate 'certificate;'

	# ON A PRIVATE BUS, NOTHING OWNS org.freedesktop.secrets. The frontend
	# builds its Secret proxy at start-up and D-Bus activation on a bus with no
	# keyring blocks for the full 25 s activation timeout before "Desktop
	# acquired" is reached. On the real session bus the machine's own value
	# stands, because there the keyring is there and the delay is not.
	if [ "$mode" != live ]; then
		xdp_conf_set "$dir/portals.conf" org.freedesktop.impl.portal.Secret 'none;'
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
