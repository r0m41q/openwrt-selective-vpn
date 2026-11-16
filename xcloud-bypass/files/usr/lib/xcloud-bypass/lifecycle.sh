#!/bin/sh

xcb_lifecycle() (
	[ "$#" -ge 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	operation=$1; shift
	case "$operation" in apply|enable|reconnect|disable|rollback|uninstall|confirm|recover|boot|event|tick) ;; *) exit 1 ;; esac
	umask 077
	runtime=$(xcb_runtime_directory) || exit 1
	if [ ! -e "$runtime/lifecycle.lock" ] && [ ! -L "$runtime/lifecycle.lock" ]; then
		(set -C; : > "$runtime/lifecycle.lock") 2>/dev/null || :
	fi
	xcb_private_file "$runtime/lifecycle.lock" || exit 1
	exec 8<> "$runtime/lifecycle.lock" || exit 1
	case "$operation" in event|tick) flock -n 8 || exit 4 ;; *) flock -w 3 8 || exit 4 ;; esac
	"xcb_life_$operation" "$@"
)

xcb_life_preflight() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	for command in timeout ubus jsonfilter nft fw4 setsid flock readlink; do
		command -v "$command" >/dev/null 2>&1 || { xcb_state_error 'A required networking utility is missing.'; exit 1; }
	done
	[ -x "$XCB_IP" ] || exit 1
	for service in openvpn pbr firewall; do [ -x "$XCB_INIT_DIR/$service" ] || exit 1; done
	timeout -s KILL 5 "$XCB_INIT_DIR/pbr" version > "$1/version" 2>/dev/null || exit 1
	[ "$(wc -c < "$1/version")" -le 1024 ] && grep -Eq '(^|[^0-9.])1\.2\.2([^0-9.]|$)' "$1/version" || {
		xcb_state_error 'This integration currently requires PBR 1.2.2.'; exit 1;
	}
	ubus -t 5 call service list '{"name":"xcloud-bypass"}' > "$1/supervisor.json" 2>/dev/null || exit 1
	[ "$(xcb_json_field "$1/supervisor.json" "@['xcloud-bypass'].instances.recovery.running")" = true ] || {
		xcb_state_error 'Start the bypass recovery service before applying changes.'; exit 1;
	}
	xcb_config_file "$XCB_CONFIG_DIR/pbr" && xcb_uci_clean pbr || exit 1
	cp "$XCB_CONFIG_DIR/pbr" "$1/pbr.preflight" && chmod 600 "$1/pbr.preflight" || exit 1
	xcb_uci_export "$1/pbr.preflight" > "$1/pbr.preflight.export" || exit 1
	xcb_uci_record pbr.config.enabled read "$1/pbr.preflight.export" > "$1/pbr.enabled" || exit 1
	if xcb_service pbr running; then
		grep -qx "[[:space:]]*option enabled '1'" "$1/pbr.enabled" && xcb_pbr_health "$1" || exit 1
	elif grep -qx "[[:space:]]*option enabled '1'" "$1/pbr.enabled"; then
		xcb_state_error 'Repair the existing PBR service before applying changes.'; exit 1
	fi
	# validate both the saved firewall and the kernel's candidate rules
	timeout -s KILL 10 fw4 check >/dev/null 2>&1
)

xcb_life_active() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	xcb_config_file "$XCB_CONFIG_DIR/xcloud-bypass" && xcb_uci_clean xcloud-bypass || exit 1
	cp "$XCB_CONFIG_DIR/xcloud-bypass" "$1/app.source" && chmod 600 "$1/app.source" || exit 1
	xcb_uci_export "$1/app.source" > "$1/app.export" || exit 1
	awk -v package=xcloud-bypass -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$1/app.export" > "$1/app.table" || exit 1
)

xcb_life_setting() {
	xcb_table_get "$1/app.table" xcloud_active "$2"
}

xcb_life_want() (
	[ "$#" -eq 4 ] && xcb_resource_target "$2" "$3" || exit 1
	case "$4" in present|missing) ;; *) exit 1 ;; esac
	{ printf '%s\n' "$4"; cat; } > "$1/wanted/$2.$3"
)

xcb_life_queue() (
	[ "$#" -eq 2 ] && xcb_state_id "$1" && xcb_private_directory "$2" || exit 1
	id=$1 work=$2
	for resource in "$work/wanted/"*; do
		[ -e "$resource" ] || continue
		xcb_private_file "$resource" || exit 1
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		presence=$(head -n 1 "$resource") || exit 1
		tail -n +2 "$resource" | xcb_transaction add "$id" "$kind" "$target" "$presence" || exit 1
	done
)

xcb_life_reconcile_ready() (
	[ "$#" -eq 3 ] && [ "${reconcile:-0}" = 1 ] || exit 1
	work=$1 network=$2 policy=$3
	for resource in "$work/wanted/"*; do
		[ -e "$resource" ] || continue
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		xcb_resource_read "$kind" "$target" "$work/current" "$work" && cmp -s "$resource" "$work/current" || exit 1
	done
	xcb_discover_live "$work" > "$work/live.final" && cmp -s "$network/live" "$work/live.final" || exit 1
	xcb_discover_leases "$work" > "$work/leases.final" && cmp -s "$network/leases.raw" "$work/leases.final" || exit 1
	xcb_network_recheck "$network" && xcb_policy_recheck "$policy" || exit 1
	xcb_vpn_ready "$work" "$(xcb_state_read "$network/client")" "$(xcb_state_read "$network/device")" &&
		xcb_pbr_ready "$work" "$(xcb_state_read "$network/interface")" "$(xcb_state_read "$network/device")" || exit 1
	if [ "$(xcb_state_read "$policy/dns")" = dnsmasq.nftset ]; then
		xcb_table_get "$policy/pbr.table" config resolver_instance | xcb_state_put "$policy/resolver_instance" || exit 1
		xcb_runtime_dns "$policy" || exit 1
	fi
)

xcb_life_obsolete() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" || exit 1
	work=$1 mode=$2
	[ -e "$XCB_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		xcb_tx_check_record "$record" || exit 1
		kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
		[ ! -e "$work/wanted/$kind.$target" ] || continue
		xcb_resource_read "$kind" "$target" "$work/current" "$work" || exit 1
		cmp -s "$record/applied" "$work/current" || {
			xcb_state_error 'A managed resource has a later edit. Resolve it before continuing.'; exit 1;
		}
		case "$mode:$kind:$target" in
			apply:option:*|apply:section:xcloud-bypass.*) continue ;;
			*:option:pbr.config.supported_interface)
				logical=$(xcb_state_read "$tx/lifecycle/after.interface") || exit 1
				[ -n "$logical" ] || logical=$(xcb_state_read "$tx/lifecycle/before.interface") || exit 1
				[ -n "$logical" ] || continue
				xcb_valid_interface "$logical" || exit 1
				if awk -F '\t' -v logical="$logical" '$1=="S" { own[$2]=($4 ~ /^xcloud_(console|browser|custom)$/) }
					$1=="V" && $3=="interface" && $4==logical && !own[$2] { found=1 }
					END { exit !found }' "$work/pbr.table"; then continue; fi
				xcb_state_mark "$work/restore_supported" 1 || exit 1 ;;
			*:option:pbr.*)
				# keep shared PBR settings when other policies may depend on them
				if awk -F '\t' '$1=="S" && $3 ~ /^(policy|dns_policy|include)$/ && $4 !~ /^xcloud_(console|browser|custom)$/ { found=1 }
					END { exit !found }' "$work/pbr.table"; then continue; fi ;;
		esac
		case "$target" in
			network.xcloud_vpn|openvpn.xcloud_client|firewall.xcloud_zone)
				if awk -F '\t' '$1=="S" { own[$2]=($4 ~ /^xcloud_(console|browser|custom)$/) }
					$1=="V" && $3=="interface" && $4=="xcloud_vpn" && !own[$2] { found=1 }
					END { exit !found }' "$work/pbr.table"; then
					xcb_state_error 'Another PBR policy uses the managed VPN. Move it before removing the VPN.'; exit 1
				fi ;;
		esac
		cp "$record/original" "$work/wanted/$kind.$target" || exit 1
	done
)

xcb_life_supported() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" && xcb_valid_interface "$2" || exit 1
	work=$1 logical=$2
	[ -e "$XCB_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
	key=$(xcb_tx_key option pbr.config.supported_interface) || exit 1
	record=$tx/manifest/$key
	[ -d "$record" ] || exit 0
	xcb_tx_check_record "$record" || exit 1
	{ printf "config pbr 'config'\n"; tail -n +2 "$record/original"; } > "$work/supported.source" || exit 1
	xcb_uci_export "$work/supported.source" > "$work/supported.export" || exit 1
	awk -v package=pbr -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/supported.export" > "$work/supported.table" || exit 1
	base=$(xcb_table_get "$work/supported.table" config supported_interface) && base=$(xcb_normalize_list identifier "$base") || exit 1
	if printf '%s\n' "$base" | grep -qxF "$logical"; then
		cp "$record/original" "$work/wanted/option.pbr.config.supported_interface" || exit 1
	else
		for value in $base "$logical"; do printf "\tlist supported_interface '%s'\n" "$value"; done |
			xcb_life_want "$work" option pbr.config.supported_interface present || exit 1
	fi
)

xcb_life_metadata() (
	[ "$#" -eq 3 ] && xcb_tx_pending "$1" && xcb_private_directory "$2" && xcb_valid_ipv4 "$3" || exit 1
	work=$2 peer=$3
	mkdir -m 700 "$tx/lifecycle" || exit 1
	meta=$tx/lifecycle
	xcb_runtime_capture "$meta" "$peer" || exit 1
	[ ! -s "$work/network/mode" ] || [ "$(xcb_state_read "$meta/ipv4_ip_forward")" = 1 ] || {
		xcb_state_error 'IPv4 forwarding must already be enabled on the router.'; exit 1;
	}
	xcb_life_active "$work" || exit 1
	for direction in before after; do
		for key in mode selection interface device client; do
			value=''
			if [ "$direction" = before ]; then
				if [ -e "$XCB_PRIVATE_DIR/confirmed" ]; then
					previous=$(xcb_tx_pointer confirmed) || exit 1
					path=$XCB_PRIVATE_DIR/transactions/$previous/lifecycle/after.$key
					[ ! -e "$path" ] || value=$(xcb_state_read "$path") || exit 1
				fi
			elif [ -e "$work/network/$key" ]; then value=$(xcb_state_read "$work/network/$key") || exit 1
			fi
			xcb_state_mark "$meta/$direction.$key" "$value" || exit 1
		done
	done
	if xcb_service pbr running; then running=1; else running=0; fi
	xcb_state_mark "$meta/pbr.before" "$running" || exit 1
	cp "$XCB_CONFIG_DIR/dhcp" "$meta/dhcp.original" && chmod 600 "$meta/dhcp.original" || exit 1
	# include every non-tunnel local subnet when checking connected routes
	xcb_discover_live "$work" > "$meta/live.before" || exit 1
	before_tun=$(xcb_state_read "$meta/before.device") && after_tun=$(xcb_state_read "$meta/after.device") || exit 1
	awk -F '\t' -v old="$before_tun" -v new="$after_tun" '
		$1=="I" { excluded[$2]=($4==old || $4==new) }
		$1=="A" && !excluded[$2] { print $3 "/" $4 }' "$meta/live.before" > "$meta/eligible" || exit 1
	if [ -e "$work/network/lan_subnets" ]; then cp "$work/network/lan_subnets" "$meta/lan_subnets" || exit 1
	else : > "$meta/lan_subnets"; fi
	if [ -e "$work/policy/dns" ]; then
		cp "$work/policy/dns" "$meta/dns" || exit 1
		if [ "$(xcb_state_read "$meta/dns")" = dnsmasq.nftset ]; then
			for name in routers destinations resolver_instance; do cp "$work/policy/$name" "$meta/$name" || exit 1; done
		fi
	else xcb_state_mark "$meta/dns" not_required || exit 1; fi
	xcb_state_budget "$XCB_PRIVATE_DIR"
)

xcb_life_changed() (
	[ "$#" -eq 2 ] && xcb_tx_load "$1" || exit 1
	for record in "$tx/changes/"*; do
		[ -e "$record" ] || continue
		target=$(xcb_state_read "$record/target") || exit 1
		[ "${target%%.*}" = "$2" ] || continue
		cmp -s "$record/original" "$record/applied" || exit 0
	done
	exit 1
)

xcb_life_services() (
	[ "$#" -eq 2 ] && xcb_tx_load "$1" || exit 1
	id=$1 direction=$2 meta=$tx/lifecycle
	case "$direction" in before|after) ;; *) exit 1 ;; esac
	mode=$(xcb_state_read "$meta/$direction.mode") || exit 1
	if [ "$direction" = after ] && xcb_tx_expired; then exit 1; fi
	logical=$(xcb_state_read "$meta/$direction.interface") || exit 1
	tun=$(xcb_state_read "$meta/$direction.device") || exit 1
	client=$(xcb_state_read "$meta/$direction.client") || exit 1
	case "$mode" in ''|managed|external) ;; *) exit 1 ;; esac
	if [ "$mode" != managed ]; then
		other=before; [ "$direction" != before ] || other=after
		if [ "$(xcb_state_read "$meta/$other.mode")" = managed ]; then xcb_service openvpn stop xcloud_client || exit 1; fi
	fi
	if xcb_life_changed "$id" network; then ubus -t 5 call network reload '{}' >/dev/null 2>&1 || exit 1; fi
	if xcb_life_changed "$id" firewall; then
		timeout -s KILL 10 fw4 check >/dev/null 2>&1 && xcb_service firewall reload || exit 1
	fi
	if [ "$mode" = managed ]; then
		if [ "$direction" = after ] && [ "${reconnect:-0}" = 1 ]; then
			xcb_service openvpn stop xcloud_client || exit 1
		fi
		xcb_service openvpn start xcloud_client || exit 1
	fi
	if [ -n "$mode" ]; then
		attempt=0
		until xcb_vpn_ready "$meta" "$client" "$tun"; do
			if [ "$direction" = after ] && xcb_tx_expired; then exit 1; fi
			[ "$attempt" -lt 12 ] || { xcb_state_error 'The VPN did not become ready.'; exit 1; }
			sleep 1; attempt=$((attempt + 1))
		done
		if [ "$logical" = xcloud_vpn ]; then xcb_vpn_attach "$id" "$logical" "$tun" || exit 1; fi
	fi
	if [ "$direction" = before ]; then running=$(xcb_state_read "$meta/pbr.before") || exit 1
	else
		xcb_resource_read option pbr.config.enabled "$meta/enabled" "$meta" || exit 1
		if grep -qx "[[:space:]]*option enabled '1'" "$meta/enabled"; then running=1; else running=0; fi
	fi
	case "$running" in 1) action=reload ;; 0) action=stop ;; *) exit 1 ;; esac
	if [ "$direction" = after ] && xcb_tx_expired; then exit 1; fi
	result=0
	if [ "$direction" = after ]; then xcb_state_mark "$meta/pbr.intent" 1 sync && sync || exit 1; fi
	xcb_pbr_reload "$meta" "$action" || result=1
	# restore forwarding even when PBR exits partway through a reload
	xcb_forward_restore "$meta" || result=1
	[ "$result" = 0 ] || exit 1
	if [ -n "$mode" ]; then xcb_pbr_ready "$meta" "$logical" "$tun" || exit 1
	elif [ "$running" = 1 ]; then xcb_pbr_health "$meta" && xcb_pbr_policies "$meta" || exit 1; fi
	if [ "$direction" = after ] && [ "$(xcb_state_read "$meta/dns")" = dnsmasq.nftset ]; then
		xcb_runtime_dns "$meta" || exit 1
	fi
	[ -n "$tun" ] || tun=xcloud_absent
	xcb_runtime_check "$meta" "$tun" "$meta/eligible"
)

xcb_lifecycle_restore() (
	[ "$#" -eq 1 ] && xcb_tx_load "$1" && xcb_private_directory "$tx/lifecycle" || exit 1
	if [ "$(xcb_state_read "$tx/boot")" != "$(xcb_boot_id)" ]; then
		xcb_boot_resolver_restore "$tx/lifecycle"
		exit
	fi
	xcb_life_services "$1" before
)

xcb_lifecycle_stop_pending() (
	[ "$#" -eq 1 ] && xcb_tx_load "$1" && xcb_private_directory "$tx/lifecycle" || exit 1
	meta=$tx/lifecycle result=0
	if [ "$(xcb_state_read "$tx/boot")" != "$(xcb_boot_id)" ]; then
		xcb_state_mark "$meta/pbr.stopped" 1 sync
		exit
	fi
	# clean the native resolver while its applied settings are still present
	xcb_pbr_reload "$meta" stop || result=1
	xcb_forward_restore "$meta" || result=1
	[ "$result" = 0 ] && xcb_state_mark "$meta/pbr.stopped" 1 sync && sync
)

xcb_life_finish() (
	[ "$#" -eq 2 ] && xcb_tx_pending "$1" && xcb_private_directory "$2" || exit 1
	id=$1 work=$2
	if [ -e "$work/preserve_shared" ] && awk -F '\t' '$1=="S" && $3 ~ /^(policy|dns_policy|include)$/ && $4 !~ /^xcloud_(console|browser|custom)$/ { found=1 }
		END { exit !found }' "$work/pbr.table"; then
		for resource in "$work/wanted/option.pbr."*; do
			[ -e "$resource" ] || continue
			target=${resource##*/option.}
			if [ "$target" = pbr.config.supported_interface ] && [ -e "$work/restore_supported" ]; then continue; fi
			xcb_resource_read option "$target" "$work/current" "$work" || exit 1
			cp "$work/current" "$resource" || exit 1
		done
	fi
	if [ "${reconcile:-0}" = 1 ]; then
		unchanged=1
		for resource in "$work/wanted/"*; do
			[ -e "$resource" ] || continue
			name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
			xcb_resource_read "$kind" "$target" "$work/current" "$work" || exit 1
			cmp -s "$resource" "$work/current" || unchanged=0
		done
	else unchanged=0; fi
	if [ "$unchanged" = 1 ]; then
		meta=$tx/lifecycle
		if xcb_vpn_ready "$meta" "$(xcb_state_read "$meta/after.client")" "$(xcb_state_read "$meta/after.device")" &&
			xcb_pbr_ready "$meta" "$(xcb_state_read "$meta/after.interface")" "$(xcb_state_read "$meta/after.device")" &&
			{ [ "$(xcb_state_read "$meta/dns")" != dnsmasq.nftset ] || xcb_runtime_dns "$meta"; }; then
			xcb_life_fingerprint "$meta" > "$work/fingerprint" &&
				xcb_state_put "$runtime/reconciled" < "$work/fingerprint" && xcb_transaction rollback "$id" || exit 1
			exit 0
		fi
	fi
	xcb_life_queue "$id" "$work" || { xcb_transaction rollback "$id"; exit 1; }
	xcb_transaction arm "$id" || { xcb_transaction rollback "$id"; exit 1; }
	# durable intent covers interruptions before the first service operation
	xcb_state_mark "$tx/lifecycle/intent" 1 sync && sync || exit 1
	if ! xcb_transaction apply "$id" || ! xcb_life_services "$id" after || ! xcb_transaction ready "$id"; then
		xcb_transaction rollback "$id" || :
		exit 1
	fi
	if [ "$unchanged" = 1 ]; then xcb_life_confirm "$id" || exit 1; fi
	xcb_life_fingerprint "$tx/lifecycle" > "$work/fingerprint" &&
		xcb_state_put "$runtime/reconciled" < "$work/fingerprint" || exit 1
	printf '%s\n' "$id"
)

xcb_life_apply() (
	[ "$#" -eq 10 ] || exit 1
	mode=$1 selection=$2 networks=$3 devices=$4 console=$5 browser=$6 fallback=$7 custom=$8 ack=$9
	shift 9; peer=$1
	case "$mode" in managed|external) ;; *) exit 1 ;; esac
	[ "$ack" = 1 ] && xcb_valid_ipv4 "$peer" && xcb_valid_bool "$console" && xcb_valid_bool "$browser" && xcb_valid_bool "$fallback" || {
		xcb_state_error 'Acknowledge the IPv4-only routing limitation before enabling.'; exit 1;
	}
	networks=$(xcb_normalize_list identifier "$networks") && devices=$(xcb_normalize_list device "$devices") &&
		custom=$(xcb_policy_destinations "$custom") || exit 1
	[ "$console$browser" != 00 ] || [ -n "$custom" ] || { xcb_state_error 'Select at least one routing destination.'; exit 1; }
	runtime=$(xcb_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/lifecycle.XXXXXXXX") || exit 1
	network='' policy='' id=''
	trap '[ -z "$network" ] || xcb_network_discard "$network"; [ -z "$policy" ] || xcb_policy_discard "$policy"; rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/wanted" || exit 1
	xcb_life_preflight "$work" || exit 1
	network=$(xcb_network_prepare "$mode" "$selection" "$networks" "$devices") || exit 1
	policy=$(xcb_policy_prepare "$network" "$console" "$browser" "$fallback" "$custom") || exit 1
	if [ -n "${xcb_review:-}" ]; then
		[ "$(xcb_routing_digest "$network" "$policy")" = "$xcb_review" ] || {
			xcb_state_error 'Routing inputs changed. Preview again before applying.'; exit 1;
		}
	fi
	# private copies retain only metadata needed for the lifecycle
	mkdir -m 700 "$work/network" "$work/policy" || exit 1
	for name in interface device client vpn_mode lan_subnets; do cp "$network/$name" "$work/network/$name" || exit 1; done
	xcb_state_mark "$work/network/mode" "$mode" && xcb_state_mark "$work/network/selection" "$selection" || exit 1
	cp "$policy/dns" "$work/policy/dns" && cp "$policy/pbr.table" "$work/pbr.table" || exit 1
	if [ "$(xcb_state_read "$policy/dns")" = dnsmasq.nftset ]; then
		for name in routers destinations; do cp "$policy/$name" "$work/policy/$name" || exit 1; done
		xcb_table_get "$policy/pbr.table" config resolver_instance | xcb_state_put "$work/policy/resolver_instance" || exit 1
	fi
	for resource in "$network/resources/"*; do
		[ -e "$resource" ] || continue
		xcb_life_want "$work" section "${resource##*/}" present < "$resource" || exit 1
	done
	for resource in "$policy/resources/"*; do
		[ -e "$resource" ] || continue
		cp "$resource" "$work/wanted/${resource##*/}" || exit 1
	done
	# all interpolated values have already passed their list validators
	{
		printf "config settings 'xcloud_active'\n\toption enabled '1'\n\toption mode '%s'\n\toption selection '%s'\n" "$mode" "$selection"
		for key in networks devices custom; do
			case "$key" in networks) value=$networks ;; devices) value=$devices ;; custom) value=$custom ;; esac
			value=$(printf '%s' "$value" | tr '\n' ' ')
			printf "\toption %s '%s'\n" "$key" "$value"
		done
		printf "\toption console '%s'\n\toption browser '%s'\n\toption fallback '%s'\n\toption ipv6_acknowledged '1'\n" "$console" "$browser" "$fallback"
	} | xcb_life_want "$work" section xcloud-bypass.xcloud_active present || exit 1
	printf "\toption enabled '1'\n" | xcb_life_want "$work" option xcloud-bypass.main.enabled present || exit 1
	xcb_life_supported "$work" "$(xcb_state_read "$network/interface")" || exit 1
	xcb_life_obsolete "$work" apply || exit 1
	# unchanged lease renewals must not write another journal to flash
	if xcb_life_reconcile_ready "$work" "$network" "$policy"; then
		confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
		xcb_life_fingerprint "$tx/lifecycle" > "$work/fingerprint" &&
			xcb_state_put "$runtime/reconciled" < "$work/fingerprint" || exit 1
		exit 0
	fi
	id=$(xcb_transaction begin) || exit 1
	xcb_life_metadata "$id" "$work" "$peer" || { xcb_transaction rollback "$id"; exit 1; }
	# recheck live scope and private profile inputs immediately before arming
	xcb_discover_live "$work" > "$work/live.final" && cmp -s "$network/live" "$work/live.final" || {
		xcb_transaction rollback "$id"; exit 1;
	}
	xcb_discover_leases "$work" > "$work/leases.final" && cmp -s "$network/leases.raw" "$work/leases.final" || {
		xcb_transaction rollback "$id"; exit 1;
	}
	xcb_network_recheck "$network" && xcb_policy_recheck "$policy" || {
		xcb_transaction rollback "$id"; exit 1;
	}
	xcb_life_finish "$id" "$work"
)

xcb_life_enable() (
	[ "$#" -eq 1 ] && xcb_valid_ipv4 "$1" || exit 1
	runtime=$(xcb_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/settings.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	xcb_life_active "$work" || exit 1
	xcb_life_apply "$(xcb_life_setting "$work" mode)" "$(xcb_life_setting "$work" selection)" \
		"$(xcb_life_setting "$work" networks)" "$(xcb_life_setting "$work" devices)" \
		"$(xcb_life_setting "$work" console)" "$(xcb_life_setting "$work" browser)" \
		"$(xcb_life_setting "$work" fallback)" "$(xcb_life_setting "$work" custom)" \
		"$(xcb_life_setting "$work" ipv6_acknowledged)" "$1"
)

xcb_life_reconnect() (
	[ "$#" -eq 1 ] && xcb_valid_ipv4 "$1" || exit 1
	runtime=$(xcb_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/reconnect.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	xcb_life_active "$work" || exit 1
	[ "$(xcb_table_get "$work/app.table" main enabled)" = 1 ] &&
		[ "$(xcb_life_setting "$work" mode)" = managed ] || exit 1
	# restart only the managed client, after the recovery journal is armed
	reconnect=1
	xcb_life_enable "$1"
)

xcb_life_remove() (
	[ "$#" -eq 2 ] && xcb_valid_ipv4 "$2" || exit 1
	mode=$1 peer=$2
	runtime=$(xcb_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/lifecycle.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/wanted" || exit 1
	xcb_state_mark "$work/preserve_shared" 1 || exit 1
	xcb_life_preflight "$work" && xcb_life_active "$work" || exit 1
	cp "$XCB_CONFIG_DIR/pbr" "$work/pbr.source" && chmod 600 "$work/pbr.source" || exit 1
	xcb_uci_export "$work/pbr.source" > "$work/pbr.export" || exit 1
	awk -v package=pbr -f "$XCB_LIBRARY_DIR/uci-inspect.awk" "$work/pbr.export" > "$work/pbr.table" || exit 1
	if [ "$mode" = rollback ]; then
		confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
		previous=$(xcb_state_read "$tx/previous") && xcb_tx_load "$previous" || {
			xcb_state_error 'There is no previous confirmed configuration.'; exit 1;
		}
		for record in "$tx/manifest/"*; do
			[ -e "$record" ] || continue
			xcb_tx_check_record "$record" || exit 1
			kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
			cp "$record/applied" "$work/wanted/$kind.$target" || exit 1
		done
		if [ -d "$tx/lifecycle" ]; then
			mkdir -m 700 "$work/network" || exit 1
			for key in mode selection interface device client; do cp "$tx/lifecycle/after.$key" "$work/network/$key" || exit 1; done
			cp "$tx/lifecycle/lan_subnets" "$work/network/lan_subnets" || exit 1
			mkdir -m 700 "$work/policy" || exit 1
			cp "$tx/lifecycle/dns" "$work/policy/dns" || exit 1
			if [ "$(xcb_state_read "$work/policy/dns")" = dnsmasq.nftset ]; then
				for name in routers destinations resolver_instance; do cp "$tx/lifecycle/$name" "$work/policy/$name" || exit 1; done
			fi
		fi
	elif [ "$mode" = disable ]; then
		xcb_uci_record xcloud-bypass.xcloud_active read "$work/app.export" > "$work/active" || exit 1
		if [ -s "$work/active" ]; then
			awk '$0 !~ /^\toption enabled / { print }' "$work/active" > "$work/inactive" || exit 1
			printf "\toption enabled '0'\n" >> "$work/inactive"
			xcb_life_want "$work" section xcloud-bypass.xcloud_active present < "$work/inactive" || exit 1
		fi
		printf "\toption enabled '0'\n" | xcb_life_want "$work" option xcloud-bypass.main.enabled present || exit 1
	fi
	xcb_life_obsolete "$work" "$mode" || exit 1
	id=$(xcb_transaction begin) || exit 1
	xcb_life_metadata "$id" "$work" "$peer" || { xcb_transaction rollback "$id"; exit 1; }
	xcb_life_finish "$id" "$work"
)

xcb_life_disable() { [ "$#" -eq 1 ] && xcb_life_remove disable "$1"; }
xcb_life_uninstall() { [ "$#" -eq 1 ] && xcb_life_remove uninstall "$1"; }
xcb_life_rollback() { [ "$#" -eq 1 ] && xcb_life_remove rollback "$1"; }

xcb_life_confirm() (
	[ "$#" -eq 1 ] && xcb_tx_pending "$1" && xcb_private_directory "$tx/lifecycle" || exit 1
	# repeat readiness checks before publishing the confirmed pointer
	meta=$tx/lifecycle
	mode=$(xcb_state_read "$meta/after.mode") && tun=$(xcb_state_read "$meta/after.device") || exit 1
	if [ -n "$mode" ]; then
		xcb_vpn_ready "$meta" "$(xcb_state_read "$meta/after.client")" "$tun" &&
			xcb_pbr_ready "$meta" "$(xcb_state_read "$meta/after.interface")" "$tun" || exit 1
	else
		xcb_resource_read option pbr.config.enabled "$meta/enabled" "$meta" || exit 1
		if grep -qx "[[:space:]]*option enabled '1'" "$meta/enabled"; then
			xcb_pbr_health "$meta" && xcb_pbr_policies "$meta" || exit 1
		elif xcb_service pbr running; then exit 1; fi
	fi
	if [ "$(xcb_state_read "$meta/dns")" = dnsmasq.nftset ]; then xcb_runtime_dns "$meta" || exit 1; fi
	[ -n "$tun" ] || tun=xcloud_absent
	xcb_runtime_check "$meta" "$tun" "$meta/eligible" && xcb_transaction confirm "$1"
)

xcb_life_recover() { [ "$#" -eq 0 ] && xcb_transaction recover; }
xcb_life_boot() { [ "$#" -eq 0 ] && xcb_transaction recover; }

xcb_life_tick() (
	[ "$#" -eq 1 ] && xcb_state_id "$1" || exit 1
	xcb_tx_load "$1" || exit 1
	case "$(xcb_state_read "$tx/state")" in runtime_recovery) xcb_transaction recover ;; *) xcb_transaction tick "$1" ;; esac
)

xcb_life_event() (
	[ "$#" -eq 0 ] || exit 1
	[ ! -e "$XCB_PRIVATE_DIR/pending" ] || exit 0
	[ -e "$XCB_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(xcb_tx_pointer confirmed) && xcb_tx_load "$confirmed" || exit 1
	[ -d "$tx/lifecycle" ] || exit 0
	mode=$(xcb_state_read "$tx/lifecycle/after.mode") || exit 1
	[ -n "$mode" ] || exit 0
	peer=$(xcb_state_read "$tx/lifecycle/peer") || exit 1
	fingerprint=$(xcb_life_fingerprint "$tx/lifecycle") || exit 1
	if [ -e "$runtime/reconciled" ] && [ "$(xcb_state_read "$runtime/reconciled")" = "$fingerprint" ]; then exit 0; fi
	# regenerated scope always needs a new confirmation after a subnet change
	reconcile=1
	xcb_life_enable "$peer"
)

xcb_life_fingerprint() (
	[ "$#" -eq 1 ] && xcb_private_directory "$1" || exit 1
	meta=$1
	runtime=$(xcb_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/fingerprint.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	{
		for package in xcloud-bypass network firewall openvpn pbr dhcp; do
			xcb_config_file "$XCB_CONFIG_DIR/$package" || exit 1
			sha256sum "$XCB_CONFIG_DIR/$package" || exit 1
		done
		if [ -e "$XCB_LEASE_FILE" ]; then
			xcb_config_file "$XCB_LEASE_FILE" && sha256sum "$XCB_LEASE_FILE" || exit 1
		fi
		xcb_discover_live "$work" > "$work/event.live" || exit 1
		sort "$work/event.live" || exit 1
		tun=$(xcb_state_read "$meta/after.device") || exit 1
		if [ -n "$tun" ]; then
			xcb_valid_netdev "$tun" || exit 1
			xcb_ip -4 -o address show dev "$tun" scope global 2>/dev/null || :
			ubus -t 5 call service list '{"name":"openvpn"}' > "$work/event.vpn" 2>/dev/null || exit 1
			[ "$(wc -c < "$work/event.vpn")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
			client=$(xcb_state_read "$meta/after.client") && xcb_valid_identifier "$client" || exit 1
			xcb_json_field "$work/event.vpn" "@.openvpn.instances.$client.running" || :
			xcb_json_field "$work/event.vpn" "@.openvpn.instances.$client.pid" || :
			logical=$(xcb_state_read "$meta/after.interface") && xcb_valid_interface "$logical" || exit 1
			xcb_config_file "$XCB_RT_TABLES" || exit 1
			table=$(awk -v name="pbr_$logical" '$2==name && $1 ~ /^[0-9]+$/ { print $1 }' "$XCB_RT_TABLES") || exit 1
			if xcb_valid_uint "$table" 999999999; then xcb_ip -4 route show table "$table" 2>/dev/null || :; fi
			xcb_ip -4 rule show 2>/dev/null || :
			if nft -j list chain inet fw4 pbr_prerouting > "$work/event.nft" 2>/dev/null; then
				[ "$(wc -c < "$work/event.nft")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
				xcb_json_field "$work/event.nft" '@.nftables[*].rule.comment' || :
			else printf '%s\n' missing_pbr_chain; fi
			if [ -f "$XCB_PBR_DNS" ] && [ ! -L "$XCB_PBR_DNS" ]; then
				[ "$(wc -c < "$XCB_PBR_DNS")" -le "$XCB_MAX_SNAPSHOT_BYTES" ] || exit 1
				sha256sum "$XCB_PBR_DNS" || exit 1
			fi
		fi
	} > "$work/event.input" || exit 1
	sha256sum "$work/event.input" | cut -d ' ' -f 1
)
