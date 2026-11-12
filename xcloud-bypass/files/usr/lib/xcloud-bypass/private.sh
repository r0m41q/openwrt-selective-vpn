#!/bin/sh

xcb_private_error() {
	printf '%s\n' 'Private storage is unavailable or has unsafe permissions.' >&2
	return 1
}

xcb_check_directory_chain() (
	[ "$#" -eq 1 ] || exit 1
	case "$1" in /*) ;; *) exit 1 ;; esac
	case "$1" in *[!a-zA-Z0-9_./-]*|*//*|*/./*|*/../*|*/.|*/..|*/) exit 1 ;; esac
	owner=$(id -u) || exit 1
	walk=$1
	while [ -n "$walk" ]; do
		[ -d "$walk" ] && [ ! -L "$walk" ] || exit 1
		info=$(stat -c '%u %a' "$walk") || exit 1
		set -- $info
		[ "$1" -eq 0 ] || [ "$1" -eq "$owner" ] || exit 1
		# allow sticky system directories such as /tmp
		if [ "$((0$2 & 0022))" -ne 0 ]; then
			[ "$1" -eq 0 ] && [ "$((0$2 & 01000))" -ne 0 ] || exit 1
		fi
		walk=${walk%/*}
	done
)

xcb_private_directory() (
	[ "$#" -eq 1 ] || exit 1
	xcb_check_directory_chain "$1" || exit 1
	[ "$(stat -c '%u %a' "$1")" = "$(id -u) 700" ]
)

xcb_private_file() (
	[ "$#" -eq 1 ] || exit 1
	[ -f "$1" ] && [ ! -L "$1" ] || exit 1
	[ "$(stat -c '%u %a %h' "$1")" = "$(id -u) 600 1" ]
)

xcb_make_private_directory() (
	[ "$#" -eq 1 ] || exit 1
	if [ ! -e "$1" ] && [ ! -L "$1" ]; then
		xcb_check_directory_chain "${1%/*}" || exit 1
		umask 077
		mkdir -m 700 -- "$1" || exit 1
	fi
	xcb_private_directory "$1"
)
