#!/bin/sh

# Source common.sh first

svpn_valid_uint() (
	[ "$#" -eq 2 ] || exit 1
	LC_ALL=C
	export LC_ALL
	case "$1" in ''|*[!0-9]*|0[0-9]*) exit 1 ;; esac
	case "$2" in ''|*[!0-9]*|0[0-9]*) exit 1 ;; esac
	# keep arithmetic within 32-bit shell limits
	[ "${#1}" -le 9 ] && [ "${#2}" -le 9 ] || exit 1
	[ "$1" -le "$2" ]
)

svpn_valid_size() (
	[ "$#" -eq 2 ] || exit 1
	LC_ALL=C
	export LC_ALL
	svpn_valid_uint "$2" 999999999 || exit 1
	[ "${#1}" -le "$2" ]
)

svpn_valid_bool() {
	[ "$#" -eq 1 ] || return 1
	case "$1" in 0|1) return 0 ;; *) return 1 ;; esac
}

svpn_valid_ipv4() (
	[ "$#" -eq 1 ] || exit 1
	case "$1" in ''|*[!0-9.]*|.*|*.) exit 1 ;; esac
	[ "${#1}" -le 15 ] || exit 1
	IFS=.
	set -f
	set -- $1
	[ "$#" -eq 4 ] || exit 1
	for octet do
		svpn_valid_uint "$octet" 255 || exit 1
	done
)

svpn_valid_cidr() (
	[ "$#" -eq 1 ] || exit 1
	case "$1" in */*) ;; *) exit 1 ;; esac
	svpn_valid_ipv4 "${1%/*}" && svpn_valid_uint "${1##*/}" 32
)

svpn_valid_subnet() (
	[ "$#" -eq 1 ] || exit 1
	svpn_valid_cidr "$1" || exit 1
	# reject host bits rather than silently expanding the network
	bits=${1##*/}
	address=${1%/*}
	IFS=.
	set -f
	set -- $address
	for octet do
		used=$bits
		[ "$used" -le 8 ] || used=8
		[ "$((octet % (1 << (8 - used))))" -eq 0 ] || exit 1
		bits=$((bits - used))
	done
)

svpn_valid_dns_name() (
	[ "$#" -eq 2 ] || exit 1
	LC_ALL=C
	export LC_ALL
	case "$2" in domain|hostname) ;; *) exit 1 ;; esac
	case "$1" in ''|*[!a-zA-Z0-9.-]*|.*|*.|*..*) exit 1 ;; esac
	[ "${#1}" -le 253 ] || exit 1
	if [ "$2" = domain ]; then
		case "$1" in *.*) ;; *) exit 1 ;; esac
	fi
	# don't interpret malformed IPv4 addresses as hostnames
	case "${1##*.}" in *[!0-9]*) ;; *) exit 1 ;; esac
	IFS=.
	set -f
	set -- $1
	for label do
		[ "${#label}" -le 63 ] || exit 1
		case "$label" in ''|-*|*-) exit 1 ;; esac
	done
)

svpn_valid_domain() {
	[ "$#" -eq 1 ] && svpn_valid_dns_name "$1" domain
}

svpn_valid_hostname() {
	[ "$#" -eq 1 ] && svpn_valid_dns_name "$1" hostname
}

svpn_valid_identifier() (
	[ "$#" -eq 1 ] || exit 1
	LC_ALL=C
	export LC_ALL
	case "$1" in ''|[!a-zA-Z_]*|*[!a-zA-Z0-9_]*) exit 1 ;; esac
	[ "${#1}" -le 63 ]
)

# A reserved name alone does not prove resource ownership.
svpn_reserved_identifier() {
	[ "$#" -eq 1 ] || return 1
	svpn_valid_identifier "$1" || return 1
	case "$1" in "${SVPN_SECTION_PREFIX}"?*) return 0 ;; *) return 1 ;; esac
}

svpn_valid_interface() {
	[ "$#" -eq 1 ] || return 1
	svpn_valid_identifier "$1" && [ "${#1}" -le 15 ]
}

svpn_valid_destination() {
	[ "$#" -eq 1 ] || return 1
	svpn_valid_ipv4 "$1" || svpn_valid_cidr "$1" || svpn_valid_domain "$1"
}

# validate the whole list before printing any entries
svpn_normalize_list() (
	[ "$#" -eq 2 ] || exit 1
	LC_ALL=C
	export LC_ALL
	case "$1" in ipv4|subnet|domain|hostname|identifier|destination) ;; *) exit 1 ;; esac
	kind=$1
	svpn_valid_size "$2" "$SVPN_MAX_LIST_BYTES" || exit 1
	IFS="$(printf ' \t')
"
	set -f
	set -- $2
	[ "$#" -le "$SVPN_MAX_LIST_ITEMS" ] || exit 1
	result=''
	seen='
'
	for item do
		case "$kind" in
			ipv4) svpn_valid_ipv4 "$item" ;;
			subnet) svpn_valid_subnet "$item" ;;
			domain) svpn_valid_domain "$item" ;;
			hostname) svpn_valid_hostname "$item" ;;
			identifier) svpn_valid_identifier "$item" ;;
			destination) svpn_valid_destination "$item" ;;
		esac || exit 1
		case "$kind" in
			domain|hostname|destination)
				item=$(printf '%s' "$item" | tr 'A-Z' 'a-z') || exit 1 ;;
		esac
		case "$seen" in *"
$item
"*) continue ;; esac
		seen="$seen$item
"
		result="$result$item
"
	done
	printf '%s' "$result"
)
