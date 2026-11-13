#!/bin/sh

xcb_policy_resource() (
	[ "$#" -eq 4 ] && xcb_resource_target "$2" "$3" || exit 1
	case "$4" in present|missing) ;; *) exit 1 ;; esac
	{ printf '%s\n' "$4"; cat; } > "$1/resources/$2.$3"
)

xcb_policy_section() (
	[ "$#" -eq 5 ] || exit 1
	printf "config policy '%s'\n\toption name '%s'\n\toption enabled '1'\n\toption interface '%s'\n\toption chain 'prerouting'\n\toption proto 'tcp'\n\toption dest_port '443'\n\toption src_addr '%s'\n\toption dest_addr '%s'\n" \
		"$1" "$2" "$3" "$4" "$5"
)

xcb_policy_owned() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	if [ ! -e "$XCB_PRIVATE_DIR/confirmed" ] && [ ! -L "$XCB_PRIVATE_DIR/confirmed" ]; then exit 0; fi
	confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		xcb_tx_check_record "$record" || exit 1
		kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
		case "$kind:$target" in section:pbr.*|option:pbr.*) ;; *) continue ;; esac
		xcb_resource_read "$kind" "$target" "$1/current" "$1" || exit 1
		cmp -s "$record/applied" "$1/current" || {
			xcb_state_error 'A managed PBR resource was edited outside the application.'; exit 1;
		}
	done
)

xcb_policy_destinations() (
	[ "$#" -eq 1 ] || exit 1
	values=$(xcb_normalize_list destination "$1") || exit 1
	set -f
	for value in $values; do
		case "$value" in
			*/*)
				xcb_valid_subnet "$value" && [ "${value##*/}" -gt 0 ] || exit 1 ;;
			*.*)
				if ! xcb_valid_ipv4 "$value"; then
					tld=${value##*.}
					case "$tld" in
						xn--?*) ;;
						*[!a-z]*|'') exit 1 ;;
						*) [ "${#tld}" -ge 2 ] || exit 1 ;;
					esac
				fi ;;
		esac
		printf '%s\n' "$value"
	done
)

xcb_dns_check() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" || exit 1
	work=$1 resolver_instance=$2
	dnsmasq --version > "$work/dnsmasq.version" 2>/dev/null || {
		xcb_state_error 'dnsmasq is missing or could not report its features.'; exit 1;
	}
	[ "$(wc -c < "$work/dnsmasq.version")" -le 8192 ] || exit 1
	awk '/^Compile time options:/ { for (i=4; i<=NF; i++) if ($i == "nftset") found=1 }
		END { exit !found }' "$work/dnsmasq.version" || {
		xcb_state_error 'Domain policies require dnsmasq with nftset support.'; exit 1;
	}
	ubus -t 5 call service list '{"name":"dnsmasq"}' > "$work/dnsmasq.service" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/dnsmasq.service")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	running=$(xcb_json_field "$work/dnsmasq.service" '@.dnsmasq.instances.*.running') || exit 1
	pid=$(xcb_json_field "$work/dnsmasq.service" '@.dnsmasq.instances.*.pid') || exit 1
	[ "$running" = true ] && xcb_valid_uint "$pid" 999999999 && [ "$pid" -gt 0 ] || {
		xcb_state_error 'One running OpenWrt dnsmasq instance is required.'; exit 1;
	}
	ss -H -4 -lnptu > "$work/listeners" 2>/dev/null || {
		xcb_state_error 'DNS listeners could not be inspected.'; exit 1;
	}
	[ "$(wc -c < "$work/listeners")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	LC_ALL=C awk -v resolver_instance="$resolver_instance" -v expected_pid="$pid" -f "$XCB_LIBRARY_DIR/dns-check.awk" \
		"$work/dhcp.table" "$work/routers" "$work/listeners" || exit 1
	printf '%s\n' 'client_dns_must_use_router' 'encrypted_dns_and_cached_answers_may_bypass_sets' >> "$work/warnings"
	xcb_state_mark "$work/dns" 'dnsmasq.nftset'
)

# only prepare resources; service changes belong to the apply lifecycle
xcb_policy_prepare() (
	[ "$#" -ge 1 ] && [ "$#" -le 5 ] && [ "$(id -u)" -eq 0 ] || exit 1
	network=$1 console=${2-1} browser=${3-0} fallback=${4-0}
	xcb_private_directory "$network" && xcb_valid_bool "$console" && xcb_valid_bool "$browser" && xcb_valid_bool "$fallback" || exit 1
	custom=$(xcb_policy_destinations "${5-}") || { xcb_state_error 'Custom destinations are invalid or unsupported.'; exit 1; }
	interface=$(xcb_state_read "$network/interface") && xcb_valid_interface "$interface" || exit 1
	scope=$(xcb_state_read "$network/scope") || exit 1
	case "$scope" in lan) kind=subnet ;; devices) kind=ipv4 ;; *) exit 1 ;; esac
	xcb_private_file "$network/sources" && [ "$(wc -c < "$network/sources")" -le "$XCB_MAX_LIST_BYTES" ] || exit 1
	sources=$(xcb_normalize_list "$kind" "$(cat "$network/sources")") || exit 1
	[ -n "$sources" ] || exit 1
	for name in lan_subnets live; do
		xcb_private_file "$network/$name" && [ "$(wc -c < "$network/$name")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
	done
	eligible=$(xcb_normalize_list subnet "$(cat "$network/lan_subnets")") || exit 1
	[ -n "$eligible" ] || exit 1
	for subnet in $eligible; do
		[ "${subnet##*/}" -gt 0 ] && [ "${subnet##*/}" -le 30 ] || exit 1
	done
	if [ "$kind" = subnet ]; then
		for source in $sources; do [ "${source##*/}" -gt 0 ] || exit 1; done
	fi
	umask 077
	runtime=$(xcb_runtime_directory) || exit 1
	count=0
	for directory in "$runtime/"policy.*; do
		[ -e "$directory" ] || [ -L "$directory" ] || continue
		xcb_private_directory "$directory" || exit 1
		count=$((count + 1))
	done
	[ "$count" -lt 8 ] && xcb_state_budget "$runtime" || {
		xcb_state_error 'Discard unused routing previews before preparing another.'; exit 1;
	}
	work=$(mktemp -d "$runtime/policy.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/resources" || exit 1
	: > "$work/warnings"
	printf '%s\n' "$sources" > "$work/sources"
	printf '%s\n' "$eligible" > "$work/lan_subnets"
	LC_ALL=C awk -v mode=scope -v scope="$scope" -f "$XCB_LIBRARY_DIR/policy-check.awk" \
		"$work/sources" "$work/lan_subnets" "$network/live" || exit 1
	source_text=$(printf '%s\n' "$sources" | tr '\n' ' ')
	source_text=${source_text% }
	xcb_config_file "$XCB_CONFIG_DIR/pbr" && xcb_uci_clean pbr || exit 1
	cp -- "$XCB_CONFIG_DIR/pbr" "$work/pbr.source" || exit 1
	xcb_uci_export "$work/pbr.source" > "$work/pbr.export" || exit 1
	awk -v package=pbr -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/pbr.export" > "$work/pbr.table" || exit 1
	awk -F '\t' '$1=="S" && $3=="pbr" && $4=="config" { found++ }
		END { exit (found != 1) }' "$work/pbr.table" || { xcb_state_error 'PBR needs its named config section.'; exit 1; }
	xcb_policy_owned "$work" || exit 1
	console_dest=''
	browser_dest=''
	if [ "$console" = 1 ]; then
		if [ "$fallback" = 1 ]; then
			console_dest='20.201.200.49 51.12.31.0'
			printf '%s\n' 'static_console_addresses_may_be_outdated' >> "$work/warnings"
		else console_dest='xsts.auth.xboxlive.com xgpuconsole.gssv-play-prod.xboxlive.com'; fi
	fi
	if [ "$browser" = 1 ]; then browser_dest='xgpuweb.gssv-play-prod.xboxlive.com xgpuwebf2p.gssv-play-prod.xboxlive.com'; fi
	printf '%s\n' "$console_dest $browser_dest" | tr ' ' '\n' > "$work/defaults"
	: > "$work/custom"
	for value in $custom; do
		grep -qxF "$value" "$work/defaults" || printf '%s\n' "$value" >> "$work/custom"
	done
	custom_dest=$(tr '\n' ' ' < "$work/custom")
	custom_dest=${custom_dest% }
	for name in console browser custom; do
		case "$name" in
			console) label='Xbox console authentication'; dest=$console_dest ;;
			browser) label='Browser xCloud authentication'; dest=$browser_dest ;;
			custom) label='Custom authentication destinations'; dest=$custom_dest ;;
		esac
		target=pbr.xcloud_$name
		xcb_resource_read section "$target" "$work/current" "$work" || exit 1
		if [ "$(head -n 1 "$work/current")" = present ]; then
			confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || {
				xcb_state_error 'A reserved PBR section already exists without matching ownership.'; exit 1;
			}
			key=$(xcb_tx_key section "$target") || exit 1
			xcb_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || exit 1
			if [ -z "$dest" ]; then xcb_policy_resource "$work" section "$target" missing < /dev/null || exit 1; fi
		fi
		[ -n "$dest" ] || continue
		xcb_policy_section "xcloud_$name" "$label" "$interface" "$source_text" "$dest" > "$work/fragment" || exit 1
		xcb_policy_resource "$work" section "$target" present < "$work/fragment" || exit 1
	done
	all_dest=$(xcb_normalize_list destination "$console_dest $browser_dest $custom_dest") || exit 1
	printf '%s\n' "$all_dest" > "$work/destinations"
	domains=0
	for value in $all_dest; do
		if ! xcb_valid_ipv4 "$value" && ! xcb_valid_cidr "$value"; then domains=1; fi
	done
	xcb_state_mark "$work/dns" not_required || exit 1
	if [ -n "$all_dest" ]; then
		printf '%s\n' 'ipv4_only_authentication_policies' >> "$work/warnings"
		netifd=$(xcb_table_get "$work/pbr.table" config netifd_enabled) || exit 1
		case "$netifd" in ''|0) ;; *) xcb_state_error 'PBR netifd extensions require separate compatibility testing.'; exit 1 ;; esac
		ignored=$(xcb_table_get "$work/pbr.table" config ignored_interface) || exit 1
		case " $ignored " in *" $interface "*) xcb_state_error 'PBR explicitly ignores the selected VPN interface.'; exit 1 ;; esac
		supported=$(xcb_table_get "$work/pbr.table" config supported_interface) || exit 1
		supported=$(xcb_normalize_list identifier "$supported") || exit 1
		if ! printf '%s\n' "$supported" | grep -qxF "$interface"; then
			{ for value in $supported "$interface"; do printf "\tlist supported_interface '%s'\n" "$value"; done; } > "$work/fragment"
			xcb_policy_resource "$work" option pbr.config.supported_interface present < "$work/fragment" || exit 1
		fi
		enabled=$(xcb_table_get "$work/pbr.table" config enabled) || exit 1
		case "$enabled" in ''|0|1) ;; *) exit 1 ;; esac
		if [ "$enabled" != 1 ]; then
			printf "\toption enabled '1'\n" | xcb_policy_resource "$work" option pbr.config.enabled present || exit 1
			printf '%s\n' 'shared_pbr_will_be_enabled' >> "$work/warnings"
		fi
	fi
	if [ "$domains" = 1 ]; then
		resolver=$(xcb_table_get "$work/pbr.table" config resolver_set) || exit 1
		case "$resolver" in ''|none|dnsmasq.nftset) ;; *) xcb_state_error 'The current PBR resolver is unsupported.'; exit 1 ;; esac
		instance=$(xcb_table_get "$work/pbr.table" config resolver_instance) || exit 1
		case "$instance" in ''|'*'|0) ;; *) xcb_valid_identifier "$instance" || exit 1 ;; esac
		for name in dhcp.table live lan_networks; do xcb_private_file "$network/$name" || exit 1; done
		xcb_config_file "$XCB_CONFIG_DIR/dhcp" && xcb_uci_clean dhcp &&
			xcb_private_file "$network/dhcp.source" && cmp -s "$network/dhcp.source" "$XCB_CONFIG_DIR/dhcp" || exit 1
		cp "$network/dhcp.source" "$work/dhcp.source" || exit 1
		xcb_uci_export "$work/dhcp.source" > "$work/dhcp.export" || exit 1
		awk -v package=dhcp -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/dhcp.export" > "$work/dhcp.table" || exit 1
		awk -F '\t' 'NR==FNR { selected[$1]=1; next }
			$1=="A" && $2 in selected { print $3 "\t" $2 }' "$network/lan_networks" "$network/live" > "$work/routers" || exit 1
		[ -s "$work/routers" ] || exit 1
		xcb_dns_check "$work" "$instance" || exit 1
		if [ "$resolver" != dnsmasq.nftset ]; then
			printf "\toption resolver_set 'dnsmasq.nftset'\n" | xcb_policy_resource "$work" option pbr.config.resolver_set present || exit 1
			printf '%s\n' 'shared_pbr_resolver_will_change' >> "$work/warnings"
		fi
	fi
	if [ -n "$all_dest" ]; then
		LC_ALL=C awk -v domains="$domains" -f "$XCB_LIBRARY_DIR/policy-check.awk" \
			"$work/pbr.table" "$work/sources" "$work/destinations" >> "$work/warnings" || exit 1
	fi
	for resource in "$work/resources/"*; do
		[ -e "$resource" ] || continue
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		xcb_resource_validate "$kind" "$target" "$resource" "$work" || exit 1
	done
	xcb_state_mark "$work/interface" "$interface" && xcb_state_mark "$work/scope" "$scope" || exit 1
	xcb_state_budget "$runtime" || exit 1
	printf '%s\n' "$work"
	trap - EXIT
)

xcb_policy_enqueue() (
	[ "$#" -eq 2 ] && [ "$(id -u)" -eq 0 ] && xcb_state_id "$1" && xcb_private_directory "$2" || exit 1
	id=$1 work=$2
	xcb_private_directory "$work/resources" && xcb_private_file "$work/pbr.source" &&
		xcb_config_file "$XCB_CONFIG_DIR/pbr" && xcb_uci_clean pbr && cmp -s "$work/pbr.source" "$XCB_CONFIG_DIR/pbr" || {
		xcb_state_error 'PBR configuration changed. Prepare it again.'; exit 1;
	}
	if [ "$(xcb_state_read "$work/dns")" = dnsmasq.nftset ]; then
		xcb_config_file "$XCB_CONFIG_DIR/dhcp" && xcb_uci_clean dhcp &&
			cmp -s "$work/dhcp.source" "$XCB_CONFIG_DIR/dhcp" || exit 1
		instance=$(xcb_table_get "$work/pbr.table" config resolver_instance) || exit 1
		xcb_dns_check "$work" "$instance" || exit 1
	fi
	for resource in "$work/resources/"*; do
		[ -e "$resource" ] || continue
		xcb_private_file "$resource" || exit 1
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		presence=$(head -n 1 "$resource") || exit 1
		tail -n +2 "$resource" | xcb_transaction add "$id" "$kind" "$target" "$presence" || exit 1
	done
)

xcb_policy_discard() (
	[ "$#" -eq 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	runtime=$(xcb_runtime_directory) || exit 1
	[ "${1%/*}" = "$runtime" ] || exit 1
	name=${1##*/}
	case "$name" in policy.????????) ;; *) exit 1 ;; esac
	case "${name#policy.}" in *[!a-zA-Z0-9]*) exit 1 ;; esac
	xcb_private_directory "$1" || exit 1
	rm -rf -- "$1"
)
