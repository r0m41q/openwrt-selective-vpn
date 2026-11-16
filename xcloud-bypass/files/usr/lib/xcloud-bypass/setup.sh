#!/bin/sh

xcb_setup_error() {
	printf '%s\n' "$1" >&2
	return 1
}

xcb_setup_read() {
	[ "$#" -eq 2 ] || return 1
	printf '%s' "$1" >&2
	IFS= read -r reply || return 1
	[ "${#reply}" -le "$2" ] || return 1
}

xcb_setup_choice() {
	while :; do
		xcb_setup_read "$1" 8 || return 1
		case "$reply" in y|Y|yes|YES) answer=1; return 0 ;; n|N|no|NO|'') answer=0; return 0 ;; esac
		printf 'Enter y or n.\n' >&2
	done
}

xcb_setup_peer() {
	peer=${SSH_CONNECTION:-}
	peer=${peer%% *}
	if ! xcb_valid_ipv4 "$peer"; then
		xcb_setup_read 'Your SSH client IPv4 address: ' 15 || return 1
		peer=$reply
		xcb_valid_ipv4 "$peer" || return 1
	fi
}

xcb_setup_secret() {
	if [ -t 0 ]; then
		tty_state=$(stty -g < /dev/tty) || return 1
		stty -echo < /dev/tty || return 1
	fi
	if ! xcb_setup_read "$1" 127; then
		if [ -n "${tty_state:-}" ]; then stty "$tty_state" < /dev/tty || :; tty_state=''; fi
		printf '\n' >&2
		return 1
	fi
	if [ -n "${tty_state:-}" ]; then stty "$tty_state" < /dev/tty || :; tty_state=''; fi
	printf '\n' >&2
}

xcb_setup_router_url() (
	[ "$#" -eq 1 ] && xcb_valid_ipv4 "$1" || exit 1
	answer=$(xcb_ip -4 route get "$1" 2>/dev/null) || exit 1
	set -f
	set -- $answer
	while [ "$#" -gt 1 ]; do
		if [ "$1" = src ] && xcb_valid_ipv4 "$2"; then
			printf 'http://%s/\n' "$2"
			exit 0
		fi
		shift
	done
	exit 1
)

xcb_setup_clients() (
	[ "$#" -eq 0 ] || exit 1
	xcb_config_file "$XCB_CONFIG_DIR/openvpn" && xcb_uci_clean openvpn || exit 1
	runtime=$(xcb_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/clients.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	cp "$XCB_CONFIG_DIR/openvpn" "$work/openvpn" && chmod 600 "$work/openvpn" || exit 1
	xcb_uci_export "$work/openvpn" > "$work/export" || exit 1
	awk -v package=openvpn -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/export" > "$work/table" || exit 1
	awk -F '\t' '$1 == "S" && $3 == "openvpn" && $4 != "-" && $4 !~ /^xcloud_/ { print $4 }' "$work/table"
)

xcb_setup_preview() (
	[ "$#" -eq 8 ] || exit 1
	network=$(xcb_network_prepare "$1" "$2" "$3" "$4") || exit 1
	trap 'xcb_network_discard "$network"; [ -z "$policy" ] || xcb_policy_discard "$policy"' EXIT
	trap 'exit 1' HUP INT TERM
	policy=''
	policy=$(xcb_policy_prepare "$network" "$5" "$6" "$7" "$8") || exit 1
	printf '\nRouting preview:\n'
	printf '  VPN: %s (%s)\n' "$2" "$1"
	if [ -n "$4" ]; then printf '  Devices: %s\n' "$4"
	elif [ -n "$3" ]; then printf '  LAN interfaces: %s\n' "$3"
	else printf '  Scope: eligible LAN networks\n'; fi
	printf '  Xbox console: %s; browser: %s; static fallback: %s\n' "$5" "$6" "$7"
	printf '  Custom destinations: %s\n' "${8:-none}"
	printf '  TCP port: 443; IPv4 only\n'
	printf '  LAN subnets: '
	tr '\n' ' ' < "$network/lan_subnets"
	printf '\n'
	printf '  DNS mode: %s\n' "$(xcb_state_read "$policy/dns")"
)

xcb_setup_wizard() (
	[ "$#" -eq 0 ] && [ "$(id -u)" -eq 0 ] || exit 1
	umask 077
	bundle='' applied=0 tty_state=''
	trap '[ -z "$tty_state" ] || stty "$tty_state" < /dev/tty; if [ "$applied" = 0 ] && [ -n "$bundle" ]; then xcb_private_directory "$bundle" && rm -rf -- "$bundle"; fi' EXIT
	trap 'exit 1' HUP INT TERM
	printf 'Xbox Cloud Gaming bypass setup\n\n'
	xcb_setup_peer || { xcb_setup_error 'A valid SSH client IPv4 address is required.'; exit 1; }
	url=$(xcb_setup_router_url "$peer" || :)
	[ -z "$url" ] || printf 'Router URL: %s\n' "$url"
	printf '1) Import a local OpenVPN profile\n2) Use an existing OpenVPN client\n' >&2
	xcb_setup_read 'Choose 1 or 2: ' 1 || exit 1
	case "$reply" in
		1)
			mode=managed
			xcb_setup_read 'Absolute path to the profile: ' 512 || exit 1
			profile=$reply
			case "$profile" in /*) ;; *) xcb_setup_error 'Enter an absolute path.'; exit 1 ;; esac
			xcb_config_file "$profile" || { xcb_setup_error 'The profile must be a safe regular file.'; exit 1; }
			xcb_make_private_directory "$XCB_PROFILE_DIR" || exit 1
			blocked=$(for old in "$XCB_PROFILE_DIR"/profile.*/client.ovpn; do
				[ -e "$old" ] || continue
				xcb_private_file "$old" || exit 1
				awk '$1 == "dev" && $2 ~ /^tun_xc[0-9]+$/ { print $2 }' "$old" || exit 1
			done) || exit 1
			tun=$(printf '%s\n' "$blocked" | xcb_select_tun) || exit 1
			selection=$(xcb_profile_import "$tun" < "$profile") || exit 1
			bundle=$selection
			selection=${selection##*/}
			if grep -qx 'auth_required=1' "$XCB_PROFILE_DIR/$selection/summary"; then
				xcb_setup_secret 'VPN username: ' || exit 1
				username=$reply
				xcb_setup_secret 'VPN password: ' || exit 1
				password=$reply
				printf '%s\n%s\n' "$username" "$password" | xcb_profile_credentials "$XCB_PROFILE_DIR/$selection" || exit 1
				unset username password reply
			fi ;;
		2)
			mode=external
			clients=$(xcb_setup_clients) || exit 1
			if [ -n "$clients" ]; then printf 'Configured OpenVPN clients:\n%s\n' "$clients" >&2; fi
			xcb_setup_read 'OpenVPN UCI client name: ' 64 || exit 1
			selection=$reply
			xcb_valid_identifier "$selection" && ! xcb_reserved_identifier "$selection" || exit 1 ;;
		*) xcb_setup_error 'Choose 1 or 2.'; exit 1 ;;
	esac
	xcb_setup_read 'LAN interface names (blank for all eligible LANs): ' "$XCB_MAX_LIST_BYTES" || exit 1
	networks=$(xcb_normalize_list identifier "$reply") || { xcb_setup_error 'Invalid LAN interface list.'; exit 1; }
	xcb_setup_read 'Device IPs or DHCP hostnames (blank for all devices): ' "$XCB_MAX_LIST_BYTES" || exit 1
	devices=$(xcb_normalize_list device "$reply") || { xcb_setup_error 'Invalid device list.'; exit 1; }
	xcb_setup_choice 'Route Xbox console authentication? [Y/n] ' || exit 1
	console=$answer
	[ -n "$reply" ] || console=1
	xcb_setup_choice 'Route browser xCloud authentication? [y/N] ' || exit 1
	browser=$answer
	xcb_setup_choice 'Use the observed two-IP fallback? [y/N] ' || exit 1
	fallback=$answer
	xcb_setup_read 'Custom domains or IPv4 destinations (blank for none): ' "$XCB_MAX_LIST_BYTES" || exit 1
	custom=$(xcb_policy_destinations "$reply") || { xcb_setup_error 'Invalid destination list.'; exit 1; }
	[ "$console$browser" != 00 ] || [ -n "$custom" ] || { xcb_setup_error 'Select a destination.'; exit 1; }
	printf '\nIPv6, client DNS bypass and DoH are outside this routing scope.\n' >&2
	xcb_setup_choice 'Acknowledge this limit? [y/N] ' || exit 1
	[ "$answer" = 1 ] || exit 1
	xcb_setup_preview "$mode" "$selection" "$networks" "$devices" "$console" "$browser" "$fallback" "$custom" || exit 1
	xcb_setup_choice 'Apply this configuration? [y/N] ' || exit 1
	[ "$answer" = 1 ] || exit 0
	applied=1
	xcb_lifecycle apply "$mode" "$selection" "$networks" "$devices" "$console" "$browser" "$fallback" "$custom" 1 "$peer" || exit 1
	id=$(xcb_tx_pointer pending) || { printf 'No confirmation is pending.\n'; exit 0; }
	printf '\nCheck that this SSH session and the router UI still work.\n'
	printf 'The change rolls back after %s seconds unless confirmed.\n' "$XCB_CONFIRM_SECONDS"
	xcb_setup_choice 'Confirm the change now? [y/N] ' || exit 1
	[ "$answer" = 1 ] || exit 0
	xcb_lifecycle confirm "$id" || exit 1
	printf 'Configuration confirmed.\n'
)

xcb_setup_uninstall() (
	[ "$#" -eq 0 ] && [ "$(id -u)" -eq 0 ] || exit 1
	xcb_setup_peer || exit 1
	xcb_setup_choice 'Remove the bypass configuration? [y/N] ' || exit 1
	[ "$answer" = 1 ] || exit 0
	xcb_lifecycle uninstall "$peer" || exit 1
	id=$(xcb_tx_pointer pending) || exit 0
	printf 'Check SSH and the router UI before confirming removal.\n'
	xcb_setup_choice 'Confirm removal now? [y/N] ' || exit 1
	[ "$answer" = 1 ] || exit 0
	xcb_lifecycle confirm "$id"
)
