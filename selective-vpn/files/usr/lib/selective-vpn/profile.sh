#!/bin/sh

# source common.sh, validate.sh and private.sh first

svpn_profile_error() {
	printf '%s\n' "$1" >&2
	return 1
}

svpn_profile_import() (
	[ "$#" -eq 1 ] || exit 1
	[ "$(id -u)" -eq 0 ] || { svpn_profile_error 'Profile import requires root.'; exit 1; }
	svpn_valid_interface "$1" || exit 1
	case "$1" in tun_sv*) ;; *) exit 1 ;; esac
	svpn_make_private_directory "$SVPN_PROFILE_DIR" || { svpn_private_error; exit 1; }
	count=0
	for bundle in "$SVPN_PROFILE_DIR"/profile.*; do
		[ ! -e "$bundle" ] || count=$((count + 1))
	done
	[ "$count" -lt 8 ] || { svpn_profile_error 'Remove unused imported profiles before importing another.'; exit 1; }
	svpn_profile_prepare "$SVPN_PROFILE_DIR" "$1"
)

# call under the configuration lock, with saved device names on stdin
svpn_select_tun() (
	[ "$#" -eq 0 ] || exit 1
	raw=$(head -c "$((SVPN_MAX_LIST_BYTES + 1))") || exit 1
	blocked=$(svpn_normalize_list identifier "$raw") || exit 1
	blocked="
$blocked
"
	index=0
	while [ "$index" -lt 64 ]; do
		candidate="tun_sv$index"
		case "$blocked" in *"
$candidate
"*) index=$((index + 1)); continue ;; esac
		if [ ! -e "/sys/class/net/$candidate" ]; then
			printf '%s\n' "$candidate"
			exit 0
		fi
		index=$((index + 1))
	done
	svpn_profile_error 'No unused tunnel name is available.'
)

# prepare a private bundle without changing the active VPN
svpn_profile_prepare() (
	[ "$#" -eq 2 ] || exit 1
	svpn_private_directory "$1" || { svpn_private_error; exit 1; }
	svpn_valid_interface "$2" || exit 1
	case "$2" in tun_sv*) ;; *) exit 1 ;; esac
	umask 077
	work=$(mktemp -d "$1/profile.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	head -c "$((SVPN_MAX_PROFILE_BYTES + 1))" > "$work/input" || exit 1
	size=$(wc -c < "$work/input") || exit 1
	if [ "$size" -eq 0 ] || [ "$size" -gt "$SVPN_MAX_PROFILE_BYTES" ]; then
		svpn_profile_error 'The profile must contain between 1 and 32768 bytes.'
		exit 1
	fi
	LC_ALL=C tr -d '\11\12\15\40-\176' < "$work/input" > "$work/invalid" || exit 1
	if [ -s "$work/invalid" ]; then
		svpn_profile_error 'The profile contains unsupported characters.'
		exit 1
	fi
	LC_ALL=C awk -v device="$2" -v credentials="$work/credentials" \
		-v output="$work/client.ovpn" -v summary="$work/summary" \
		-f "$SVPN_LIBRARY_DIR/profile.awk" "$work/input" || exit 1
	svpn_private_file "$work/client.ovpn" && svpn_private_file "$work/summary" || exit 1
	rm -f -- "$work/input" "$work/invalid" || exit 1
	printf '%s\n' "$work"
	trap - EXIT
)

# username and password arrive as two lines on stdin, never as arguments
svpn_profile_credentials() (
	[ "$#" -eq 1 ] || exit 1
	svpn_private_directory "$1" && svpn_private_file "$1/summary" || {
		svpn_private_error; exit 1
	}
	grep -qx 'auth_required=1' "$1/summary" || {
		svpn_profile_error 'This profile does not use username/password authentication.'
		exit 1
	}
	if [ -e "$1/credentials" ] || [ -L "$1/credentials" ]; then
		svpn_private_file "$1/credentials" || { svpn_private_error; exit 1; }
	fi
	umask 077
	work=$(mktemp -d "$1/.credentials.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	head -c 257 > "$work/input" || exit 1
	LC_ALL=C tr -d '\12\40-\176\200-\377' < "$work/input" > "$work/invalid" || exit 1
	[ ! -s "$work/invalid" ] && LC_ALL=C awk '
		length($0) < 1 || length($0) > 127 { bad = 1 }
		END { exit (bad || NR != 2) }
	' "$work/input" || {
		svpn_profile_error 'Enter a username and password of 1 to 127 bytes each, without control characters.'
		exit 1
	}
	mv -f -- "$work/input" "$1/credentials" || exit 1
	svpn_private_file "$1/credentials"
)
