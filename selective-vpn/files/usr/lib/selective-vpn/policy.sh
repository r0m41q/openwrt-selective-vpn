#!/bin/sh

. "$SVPN_LIBRARY_DIR/rules.sh"

svpn_policy_resource() (
	[ "$#" -eq 4 ] && svpn_resource_target "$2" "$3" || exit 1
	case "$4" in present|missing) ;; *) exit 1 ;; esac
	{ printf '%s\n' "$4"; cat; } > "$1/resources/$2.$3"
)

svpn_policy_section() (
	[ "$#" -ge 5 ] && [ "$#" -le 7 ] || exit 1
	printf "config policy '%s'\n\toption name '%s'\n\toption enabled '1'\n\toption interface '%s'\n\toption chain 'prerouting'\n\toption proto '%s'\n\toption dest_port '%s'\n\toption src_addr '%s'\n\toption dest_addr '%s'\n" \
		"$1" "$2" "$3" "${6-tcp}" "${7-443}" "$4" "$5"
)

svpn_policy_owned() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	: > "$1/pbr.owned"
	if [ ! -e "$SVPN_PRIVATE_DIR/confirmed" ] && [ ! -L "$SVPN_PRIVATE_DIR/confirmed" ]; then exit 0; fi
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		svpn_tx_check_record "$record" || exit 1
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
		case "$kind:$target" in section:pbr.*|option:pbr.*) ;; *) continue ;; esac
		[ "$kind" != section ] || printf '%s\n' "${target#pbr.}" >> "$1/pbr.owned"
		svpn_resource_read "$kind" "$target" "$1/current" "$1" || exit 1
		cmp -s "$record/applied" "$1/current" || {
			svpn_state_error 'A managed PBR resource was edited outside the application.'; exit 1;
		}
	done
)

svpn_policy_destinations() (
	[ "$#" -eq 1 ] || exit 1
	values=$(svpn_normalize_list destination "$1") || exit 1
	set -f
	for value in $values; do
		case "$value" in
			*/*)
				svpn_valid_subnet "$value" && [ "${value##*/}" -gt 0 ] || exit 1 ;;
			*.*)
				if ! svpn_valid_ipv4 "$value"; then
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

svpn_dns_check() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" || exit 1
	work=$1 resolver_instance=$2
	dnsmasq --version > "$work/dnsmasq.version" 2>/dev/null || {
		svpn_state_error 'dnsmasq is missing or could not report its features.'; exit 1;
	}
	[ "$(wc -c < "$work/dnsmasq.version")" -le 8192 ] || exit 1
	awk '/^Compile time options:/ { for (i=4; i<=NF; i++) if ($i == "nftset") found=1 }
		END { exit !found }' "$work/dnsmasq.version" || {
		svpn_state_error 'Domain policies require dnsmasq with nftset support.'; exit 1;
	}
	ubus -t 5 call service list '{"name":"dnsmasq"}' > "$work/dnsmasq.service" 2>/dev/null || exit 1
	[ "$(wc -c < "$work/dnsmasq.service")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	running=$(svpn_json_field "$work/dnsmasq.service" '@.dnsmasq.instances.*.running') || exit 1
	pid=$(svpn_json_field "$work/dnsmasq.service" '@.dnsmasq.instances.*.pid') || exit 1
	[ "$running" = true ] && svpn_valid_uint "$pid" 999999999 && [ "$pid" -gt 0 ] || {
		svpn_state_error 'One running OpenWrt dnsmasq instance is required.'; exit 1;
	}
	ss -H -4 -lnptu > "$work/listeners" 2>/dev/null || {
		svpn_state_error 'DNS listeners could not be inspected.'; exit 1;
	}
	[ "$(wc -c < "$work/listeners")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	LC_ALL=C awk -v resolver_instance="$resolver_instance" -v expected_pid="$pid" -f "$SVPN_LIBRARY_DIR/dns-check.awk" \
		"$work/dhcp.table" "$work/routers" "$work/listeners" || exit 1
	printf '%s\n' 'client_dns_must_use_router' 'encrypted_dns_and_cached_answers_may_bypass_sets' >> "$work/warnings"
	svpn_state_mark "$work/dns" 'dnsmasq.nftset'
)

# only prepare resources; service changes belong to the apply lifecycle
svpn_policy_prepare() (
	[ "$#" -ge 1 ] && [ "$#" -le 5 ] && [ "$(id -u)" -eq 0 ] || exit 1
	network=$1 console=${2-0} browser=${3-0} fallback=${4-0}
	use_rules=0
	if [ "$#" -eq 1 ] || [ -n "${svpn_rules:-}" ]; then use_rules=1; fi
	svpn_private_directory "$network" && svpn_valid_bool "$console" && svpn_valid_bool "$browser" && svpn_valid_bool "$fallback" || exit 1
	custom=$(svpn_policy_destinations "${5-}") || { svpn_state_error 'Custom destinations are invalid or unsupported.'; exit 1; }
	interface=$(svpn_state_read "$network/interface") && svpn_valid_interface "$interface" || exit 1
	scope=$(svpn_state_read "$network/scope") || exit 1
	[ "$use_rules" = 0 ] || [ "$scope" = lan ] || exit 1
	case "$scope" in lan) kind=subnet ;; devices) kind=ipv4 ;; *) exit 1 ;; esac
	svpn_private_file "$network/sources" && [ "$(wc -c < "$network/sources")" -le "$SVPN_MAX_LIST_BYTES" ] || exit 1
	sources=$(svpn_normalize_list "$kind" "$(cat "$network/sources")") || exit 1
	[ -n "$sources" ] || exit 1
	for name in lan_subnets live; do
		svpn_private_file "$network/$name" && [ "$(wc -c < "$network/$name")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
	done
	eligible=$(svpn_normalize_list subnet "$(cat "$network/lan_subnets")") || exit 1
	[ -n "$eligible" ] || exit 1
	for subnet in $eligible; do
		[ "${subnet##*/}" -gt 0 ] && [ "${subnet##*/}" -le 30 ] || exit 1
	done
	if [ "$kind" = subnet ]; then
		for source in $sources; do [ "${source##*/}" -gt 0 ] || exit 1; done
	fi
	umask 077
	runtime=$(svpn_runtime_directory) || exit 1
	count=0
	for directory in "$runtime/"policy.*; do
		[ -e "$directory" ] || [ -L "$directory" ] || continue
		svpn_private_directory "$directory" || exit 1
		count=$((count + 1))
	done
	[ "$count" -lt 8 ] && svpn_state_budget "$runtime" || {
		svpn_state_error 'Discard unused routing previews before preparing another.'; exit 1;
	}
	work=$(mktemp -d "$runtime/policy.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/resources" || exit 1
	: > "$work/warnings"
	printf '%s\n' "$sources" > "$work/sources"
	printf '%s\n' "$eligible" > "$work/lan_subnets"
	LC_ALL=C awk -v mode=scope -v scope="$scope" -f "$SVPN_LIBRARY_DIR/policy-check.awk" \
		"$work/sources" "$work/lan_subnets" "$network/live" || exit 1
	source_text=$(printf '%s\n' "$sources" | tr '\n' ' ')
	source_text=${source_text% }
	svpn_config_file "$SVPN_CONFIG_DIR/pbr" && svpn_uci_clean pbr || exit 1
	cp -- "$SVPN_CONFIG_DIR/pbr" "$work/pbr.source" || exit 1
	svpn_uci_export "$work/pbr.source" > "$work/pbr.export" || exit 1
	awk -v package=pbr -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/pbr.export" > "$work/pbr.table" || exit 1
	awk -F '\t' '$1=="S" && $3=="pbr" && $4=="config" { found++ }
		END { exit (found != 1) }' "$work/pbr.table" || { svpn_state_error 'PBR needs its named config section.'; exit 1; }
	svpn_policy_owned "$work" || exit 1
	if [ "$use_rules" = 1 ]; then
		svpn_rules_prepare "$work" "$network" && svpn_rules_policies "$work" "$interface" || exit 1
		all_dest=$(cat "$work/destinations") || exit 1
	else
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
				console) label='Console authentication'; dest=$console_dest ;;
				browser) label='Browser service authentication'; dest=$browser_dest ;;
				custom) label='Custom authentication destinations'; dest=$custom_dest ;;
			esac
			target=pbr.svpn_$name
			svpn_resource_read section "$target" "$work/current" "$work" || exit 1
			if [ "$(head -n 1 "$work/current")" = present ]; then
				confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || {
					svpn_state_error 'A reserved PBR section already exists without matching ownership.'; exit 1;
				}
				key=$(svpn_tx_key section "$target") || exit 1
				svpn_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || exit 1
				if [ -z "$dest" ]; then svpn_policy_resource "$work" section "$target" missing < /dev/null || exit 1; fi
			fi
			[ -n "$dest" ] || continue
			svpn_policy_section "svpn_$name" "$label" "$interface" "$source_text" "$dest" > "$work/fragment" || exit 1
			svpn_policy_resource "$work" section "$target" present < "$work/fragment" || exit 1
		done
		all_dest=$(svpn_normalize_list destination "$console_dest $browser_dest $custom_dest") || exit 1
		printf '%s\n' "$all_dest" > "$work/destinations"
	fi
	domains=0
	for value in $all_dest; do
		if ! svpn_valid_ipv4 "$value" && ! svpn_valid_cidr "$value"; then domains=1; fi
	done
	svpn_state_mark "$work/dns" not_required || exit 1
	if [ -n "$all_dest" ]; then
		printf '%s\n' 'ipv4_only_routing_policies' >> "$work/warnings"
		netifd=$(svpn_table_get "$work/pbr.table" config netifd_enabled) || exit 1
		case "$netifd" in ''|0) ;; *) svpn_state_error 'PBR netifd extensions require separate compatibility testing.'; exit 1 ;; esac
		ignored=$(svpn_table_get "$work/pbr.table" config ignored_interface) || exit 1
		case " $ignored " in *" $interface "*) svpn_state_error 'PBR explicitly ignores the selected VPN interface.'; exit 1 ;; esac
		supported=$(svpn_table_get "$work/pbr.table" config supported_interface) || exit 1
		supported=$(svpn_normalize_list identifier "$supported") || exit 1
		if ! printf '%s\n' "$supported" | grep -qxF "$interface"; then
			{ for value in $supported "$interface"; do printf "\tlist supported_interface '%s'\n" "$value"; done; } > "$work/fragment"
			svpn_policy_resource "$work" option pbr.config.supported_interface present < "$work/fragment" || exit 1
		fi
		enabled=$(svpn_table_get "$work/pbr.table" config enabled) || exit 1
		case "$enabled" in ''|0|1) ;; *) exit 1 ;; esac
		if [ "$enabled" != 1 ]; then
			printf "\toption enabled '1'\n" | svpn_policy_resource "$work" option pbr.config.enabled present || exit 1
			printf '%s\n' 'shared_pbr_will_be_enabled' >> "$work/warnings"
		fi
	fi
	if [ "$domains" = 1 ]; then
		resolver=$(svpn_table_get "$work/pbr.table" config resolver_set) || exit 1
		case "$resolver" in ''|none|dnsmasq.nftset) ;; *) svpn_state_error 'The current PBR resolver is unsupported.'; exit 1 ;; esac
		instance=$(svpn_table_get "$work/pbr.table" config resolver_instance) || exit 1
		case "$instance" in ''|'*'|0) ;; *) svpn_valid_identifier "$instance" || exit 1 ;; esac
		for name in dhcp.table live lan_networks; do svpn_private_file "$network/$name" || exit 1; done
		svpn_config_file "$SVPN_CONFIG_DIR/dhcp" && svpn_uci_clean dhcp &&
			svpn_private_file "$network/dhcp.source" && cmp -s "$network/dhcp.source" "$SVPN_CONFIG_DIR/dhcp" || exit 1
		cp "$network/dhcp.source" "$work/dhcp.source" || exit 1
		svpn_uci_export "$work/dhcp.source" > "$work/dhcp.export" || exit 1
		awk -v package=dhcp -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/dhcp.export" > "$work/dhcp.table" || exit 1
		awk -F '\t' 'NR==FNR { selected[$1]=1; next }
			$1=="A" && $2 in selected { print $3 "\t" $2 }' "$network/lan_networks" "$network/live" > "$work/routers" || exit 1
		[ -s "$work/routers" ] || exit 1
		svpn_dns_check "$work" "$instance" || exit 1
		if [ "$resolver" != dnsmasq.nftset ]; then
			printf "\toption resolver_set 'dnsmasq.nftset'\n" | svpn_policy_resource "$work" option pbr.config.resolver_set present || exit 1
			printf '%s\n' 'shared_pbr_resolver_will_change' >> "$work/warnings"
		fi
	fi
	if [ -n "$all_dest" ]; then
		LC_ALL=C awk -v domains="$domains" -v generic="$use_rules" -f "$SVPN_LIBRARY_DIR/policy-check.awk" \
			"$work/pbr.owned" "$work/pbr.table" "$work/sources" "$work/destinations" >> "$work/warnings" || exit 1
	fi
	for resource in "$work/resources/"*; do
		[ -e "$resource" ] || continue
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		svpn_resource_validate "$kind" "$target" "$resource" "$work" || exit 1
	done
	svpn_state_mark "$work/interface" "$interface" && svpn_state_mark "$work/scope" "$scope" || exit 1
	svpn_state_budget "$runtime" || exit 1
	printf '%s\n' "$work"
	trap - EXIT
)

svpn_policy_recheck() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	umask 077
	work=$1
	if [ -e "$work/app.source" ]; then
		svpn_config_file "$SVPN_CONFIG_DIR/selective-vpn" && svpn_uci_clean selective-vpn &&
			cmp -s "$work/app.source" "$SVPN_CONFIG_DIR/selective-vpn" || exit 1
	fi
	svpn_private_directory "$work/resources" && svpn_private_file "$work/pbr.source" &&
		svpn_config_file "$SVPN_CONFIG_DIR/pbr" && svpn_uci_clean pbr && cmp -s "$work/pbr.source" "$SVPN_CONFIG_DIR/pbr" || {
		svpn_state_error 'PBR configuration changed. Prepare it again.'; exit 1;
	}
	if [ "$(svpn_state_read "$work/dns")" = dnsmasq.nftset ]; then
		svpn_config_file "$SVPN_CONFIG_DIR/dhcp" && svpn_uci_clean dhcp &&
			cmp -s "$work/dhcp.source" "$SVPN_CONFIG_DIR/dhcp" || exit 1
		instance=$(svpn_table_get "$work/pbr.table" config resolver_instance) || exit 1
		svpn_dns_check "$work" "$instance" || exit 1
	fi
)

svpn_policy_enqueue() (
	[ "$#" -eq 2 ] && [ "$(id -u)" -eq 0 ] && svpn_state_id "$1" && svpn_private_directory "$2" || exit 1
	id=$1 work=$2
	svpn_policy_recheck "$work" || exit 1
	for resource in "$work/resources/"*; do
		[ -e "$resource" ] || continue
		svpn_private_file "$resource" || exit 1
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		presence=$(head -n 1 "$resource") || exit 1
		tail -n +2 "$resource" | svpn_transaction add "$id" "$kind" "$target" "$presence" || exit 1
	done
)

svpn_policy_discard() (
	[ "$#" -eq 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	runtime=$(svpn_runtime_directory) || exit 1
	[ "${1%/*}" = "$runtime" ] || exit 1
	name=${1##*/}
	case "$name" in policy.????????) ;; *) exit 1 ;; esac
	case "${name#policy.}" in *[!a-zA-Z0-9]*) exit 1 ;; esac
	svpn_private_directory "$1" || exit 1
	rm -rf -- "$1"
)
