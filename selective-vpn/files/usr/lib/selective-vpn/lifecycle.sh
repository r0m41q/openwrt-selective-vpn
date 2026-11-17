#!/bin/sh

svpn_lifecycle() (
	[ "$#" -ge 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	operation=$1; shift
	case "$operation" in apply|enable|reconnect|disable|rollback|uninstall|confirm|recover|boot|event|tick) ;; *) exit 1 ;; esac
	umask 077
	runtime=$(svpn_runtime_directory) || exit 1
	if [ ! -e "$runtime/lifecycle.lock" ] && [ ! -L "$runtime/lifecycle.lock" ]; then
		(set -C; : > "$runtime/lifecycle.lock") 2>/dev/null || :
	fi
	svpn_private_file "$runtime/lifecycle.lock" || exit 1
	exec 8<> "$runtime/lifecycle.lock" || exit 1
	case "$operation" in event|tick) flock -n 8 || exit 4 ;; *) flock -w 3 8 || exit 4 ;; esac
	"svpn_life_$operation" "$@"
)

svpn_life_preflight() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	for command in timeout ubus jsonfilter nft fw4 setsid flock readlink; do
		command -v "$command" >/dev/null 2>&1 || { svpn_state_error 'A required networking utility is missing.'; exit 1; }
	done
	[ -x "$SVPN_IP" ] || exit 1
	for service in openvpn pbr firewall; do [ -x "$SVPN_INIT_DIR/$service" ] || exit 1; done
	timeout -s KILL 5 "$SVPN_INIT_DIR/pbr" version > "$1/version" 2>/dev/null || exit 1
	[ "$(wc -c < "$1/version")" -le 1024 ] && grep -Eq '(^|[^0-9.])1\.2\.2([^0-9.]|$)' "$1/version" || {
		svpn_state_error 'This integration currently requires PBR 1.2.2.'; exit 1;
	}
	ubus -t 5 call service list '{"name":"selective-vpn"}' > "$1/supervisor.json" 2>/dev/null || exit 1
	[ "$(svpn_json_field "$1/supervisor.json" "@['selective-vpn'].instances.recovery.running")" = true ] || {
		svpn_state_error 'Start the routing recovery service before applying changes.'; exit 1;
	}
	svpn_config_file "$SVPN_CONFIG_DIR/pbr" && svpn_uci_clean pbr || exit 1
	cp "$SVPN_CONFIG_DIR/pbr" "$1/pbr.preflight" && chmod 600 "$1/pbr.preflight" || exit 1
	svpn_uci_export "$1/pbr.preflight" > "$1/pbr.preflight.export" || exit 1
	svpn_uci_record pbr.config.enabled read "$1/pbr.preflight.export" > "$1/pbr.enabled" || exit 1
	if svpn_service pbr running; then
		grep -qx "[[:space:]]*option enabled '1'" "$1/pbr.enabled" && svpn_pbr_health "$1" || exit 1
	elif grep -qx "[[:space:]]*option enabled '1'" "$1/pbr.enabled"; then
		svpn_state_error 'Repair the existing PBR service before applying changes.'; exit 1
	fi
	# validate both the saved firewall and the kernel's candidate rules
	timeout -s KILL 10 fw4 check >/dev/null 2>&1
)

svpn_life_active() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	svpn_config_file "$SVPN_CONFIG_DIR/selective-vpn" && svpn_uci_clean selective-vpn || exit 1
	cp "$SVPN_CONFIG_DIR/selective-vpn" "$1/app.source" && chmod 600 "$1/app.source" || exit 1
	svpn_uci_export "$1/app.source" > "$1/app.export" || exit 1
	awk -v package=selective-vpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$1/app.export" > "$1/app.table" || exit 1
)

svpn_life_setting() {
	svpn_table_get "$1/app.table" svpn_active "$2"
}

svpn_life_want() (
	[ "$#" -eq 4 ] && svpn_resource_target "$2" "$3" || exit 1
	case "$4" in present|missing) ;; *) exit 1 ;; esac
	{ printf '%s\n' "$4"; cat; } > "$1/wanted/$2.$3"
)

svpn_life_queue() (
	[ "$#" -eq 2 ] && svpn_state_id "$1" && svpn_private_directory "$2" || exit 1
	id=$1 work=$2
	for resource in "$work/wanted/"*; do
		[ -e "$resource" ] || continue
		svpn_private_file "$resource" || exit 1
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		presence=$(head -n 1 "$resource") || exit 1
		tail -n +2 "$resource" | svpn_transaction add "$id" "$kind" "$target" "$presence" || exit 1
	done
)

svpn_life_reconcile_ready() (
	[ "$#" -eq 3 ] && [ "${reconcile:-0}" = 1 ] || exit 1
	work=$1 network=$2 policy=$3
	for resource in "$work/wanted/"*; do
		[ -e "$resource" ] || continue
		name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
		svpn_resource_read "$kind" "$target" "$work/current" "$work" && cmp -s "$resource" "$work/current" || exit 1
	done
	svpn_discover_live "$work" > "$work/live.final" && cmp -s "$network/live" "$work/live.final" || exit 1
	svpn_network_recheck "$network" && svpn_policy_recheck "$policy" || exit 1
	svpn_vpn_ready "$work" "$(svpn_state_read "$network/client")" "$(svpn_state_read "$network/device")" &&
		svpn_pbr_ready "$work" "$(svpn_state_read "$network/interface")" "$(svpn_state_read "$network/device")" || exit 1
	if [ "$(svpn_state_read "$policy/dns")" = dnsmasq.nftset ]; then
		svpn_table_get "$policy/pbr.table" config resolver_instance | svpn_state_put "$policy/resolver_instance" || exit 1
		svpn_runtime_dns "$policy" || exit 1
	fi
)

svpn_life_pbr_owned() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	: > "$1/pbr.owned"
	[ -e "$SVPN_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		svpn_tx_check_record "$record" || exit 1
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
		case "$kind:$target" in section:pbr.*) printf '%s\n' "${target#pbr.}" >> "$1/pbr.owned" ;; esac
	done
)

svpn_life_obsolete() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" || exit 1
	work=$1 mode=$2
	svpn_life_pbr_owned "$work" || exit 1
	[ -e "$SVPN_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		svpn_tx_check_record "$record" || exit 1
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
		[ ! -e "$work/wanted/$kind.$target" ] || continue
		svpn_resource_read "$kind" "$target" "$work/current" "$work" || exit 1
		cmp -s "$record/applied" "$work/current" || {
			svpn_state_error 'A managed resource has a later edit. Resolve it before continuing.'; exit 1;
		}
		case "$mode:$kind:$target" in
			apply:section:selective-vpn.svpn_rule_*) ;;
			apply:option:*|apply:section:selective-vpn.*) continue ;;
			*:option:pbr.config.supported_interface)
				logical=$(svpn_state_read "$tx/lifecycle/after.interface") || exit 1
				[ -n "$logical" ] || logical=$(svpn_state_read "$tx/lifecycle/before.interface") || exit 1
				[ -n "$logical" ] || continue
				svpn_valid_interface "$logical" || exit 1
				if awk -F '\t' -v logical="$logical" 'FILENAME ~ /pbr\.owned$/ { names[$1]=1; next }
					$1=="S" { own[$2]=($4 in names) }
					$1=="V" && $3=="interface" && $4==logical && !own[$2] { found=1 }
					END { exit !found }' "$work/pbr.owned" "$work/pbr.table"; then continue; fi
				svpn_state_mark "$work/restore_supported" 1 || exit 1 ;;
			*:option:pbr.*)
				# keep shared PBR settings when other policies may depend on them
				if awk -F '\t' 'FILENAME ~ /pbr\.owned$/ { names[$1]=1; next }
					$1=="S" && $3 ~ /^(policy|dns_policy|include)$/ && !($4 in names) { found=1 }
					END { exit !found }' "$work/pbr.owned" "$work/pbr.table"; then continue; fi ;;
		esac
		case "$target" in
			network.svpn_vpn|openvpn.svpn_client|firewall.svpn_zone)
				if awk -F '\t' 'FILENAME ~ /pbr\.owned$/ { names[$1]=1; next }
					$1=="S" { own[$2]=($4 in names) }
					$1=="V" && $3=="interface" && $4=="svpn_vpn" && !own[$2] { found=1 }
					END { exit !found }' "$work/pbr.owned" "$work/pbr.table"; then
					svpn_state_error 'Another PBR policy uses the managed VPN. Move it before removing the VPN.'; exit 1
				fi ;;
		esac
		cp "$record/original" "$work/wanted/$kind.$target" || exit 1
	done
)

svpn_life_supported() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" && svpn_valid_interface "$2" || exit 1
	work=$1 logical=$2
	[ -e "$SVPN_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	key=$(svpn_tx_key option pbr.config.supported_interface) || exit 1
	record=$tx/manifest/$key
	[ -d "$record" ] || exit 0
	svpn_tx_check_record "$record" || exit 1
	{ printf "config pbr 'config'\n"; tail -n +2 "$record/original"; } > "$work/supported.source" || exit 1
	svpn_uci_export "$work/supported.source" > "$work/supported.export" || exit 1
	awk -v package=pbr -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/supported.export" > "$work/supported.table" || exit 1
	base=$(svpn_table_get "$work/supported.table" config supported_interface) && base=$(svpn_normalize_list identifier "$base") || exit 1
	if printf '%s\n' "$base" | grep -qxF "$logical"; then
		cp "$record/original" "$work/wanted/option.pbr.config.supported_interface" || exit 1
	else
		for value in $base "$logical"; do printf "\tlist supported_interface '%s'\n" "$value"; done |
			svpn_life_want "$work" option pbr.config.supported_interface present || exit 1
	fi
)

svpn_life_metadata() (
	[ "$#" -eq 3 ] && svpn_tx_pending "$1" && svpn_private_directory "$2" && svpn_valid_ipv4 "$3" || exit 1
	work=$2 peer=$3
	mkdir -m 700 "$tx/lifecycle" || exit 1
	meta=$tx/lifecycle
	svpn_runtime_capture "$meta" "$peer" || exit 1
	[ ! -s "$work/network/mode" ] || [ "$(svpn_state_read "$meta/ipv4_ip_forward")" = 1 ] || {
		svpn_state_error 'IPv4 forwarding must already be enabled on the router.'; exit 1;
	}
	svpn_life_active "$work" || exit 1
	for direction in before after; do
		for key in mode selection interface device client; do
			value=''
			if [ "$direction" = before ]; then
				if [ -e "$SVPN_PRIVATE_DIR/confirmed" ]; then
					previous=$(svpn_tx_pointer confirmed) || exit 1
					path=$SVPN_PRIVATE_DIR/transactions/$previous/lifecycle/after.$key
					[ ! -e "$path" ] || value=$(svpn_state_read "$path") || exit 1
				fi
			elif [ -e "$work/network/$key" ]; then value=$(svpn_state_read "$work/network/$key") || exit 1
			fi
			svpn_state_mark "$meta/$direction.$key" "$value" || exit 1
		done
	done
	if svpn_service pbr running; then running=1; else running=0; fi
	svpn_state_mark "$meta/pbr.before" "$running" || exit 1
	cp "$SVPN_CONFIG_DIR/dhcp" "$meta/dhcp.original" && chmod 600 "$meta/dhcp.original" || exit 1
	# include every non-tunnel local subnet when checking connected routes
	svpn_discover_live "$work" > "$meta/live.before" || exit 1
	before_tun=$(svpn_state_read "$meta/before.device") && after_tun=$(svpn_state_read "$meta/after.device") || exit 1
	awk -F '\t' -v old="$before_tun" -v new="$after_tun" '
		$1=="I" { excluded[$2]=($4==old || $4==new) }
		$1=="A" && !excluded[$2] { print $3 "/" $4 }' "$meta/live.before" > "$meta/eligible" || exit 1
	if [ -e "$work/network/lan_subnets" ]; then cp "$work/network/lan_subnets" "$meta/lan_subnets" || exit 1
	else : > "$meta/lan_subnets"; fi
	if [ -e "$work/policy/dns" ]; then
		cp "$work/policy/dns" "$meta/dns" || exit 1
		if [ "$(svpn_state_read "$meta/dns")" = dnsmasq.nftset ]; then
			for name in routers destinations resolver_instance; do cp "$work/policy/$name" "$meta/$name" || exit 1; done
		fi
	else svpn_state_mark "$meta/dns" not_required || exit 1; fi
	svpn_state_budget "$SVPN_PRIVATE_DIR"
)

svpn_life_changed() (
	[ "$#" -eq 2 ] && svpn_tx_load "$1" || exit 1
	for record in "$tx/changes/"*; do
		[ -e "$record" ] || continue
		target=$(svpn_state_read "$record/target") || exit 1
		[ "${target%%.*}" = "$2" ] || continue
		cmp -s "$record/original" "$record/applied" || exit 0
	done
	exit 1
)

svpn_life_services() (
	[ "$#" -eq 2 ] && svpn_tx_load "$1" || exit 1
	id=$1 direction=$2 meta=$tx/lifecycle
	case "$direction" in before|after) ;; *) exit 1 ;; esac
	mode=$(svpn_state_read "$meta/$direction.mode") || exit 1
	if [ "$direction" = after ] && svpn_tx_expired; then exit 1; fi
	logical=$(svpn_state_read "$meta/$direction.interface") || exit 1
	tun=$(svpn_state_read "$meta/$direction.device") || exit 1
	client=$(svpn_state_read "$meta/$direction.client") || exit 1
	case "$mode" in ''|managed|external) ;; *) exit 1 ;; esac
	if [ "$mode" != managed ]; then
		other=before; [ "$direction" != before ] || other=after
		if [ "$(svpn_state_read "$meta/$other.mode")" = managed ]; then svpn_service openvpn stop svpn_client || exit 1; fi
	fi
	if svpn_life_changed "$id" network; then ubus -t 5 call network reload '{}' >/dev/null 2>&1 || exit 1; fi
	if svpn_life_changed "$id" firewall; then
		timeout -s KILL 10 fw4 check >/dev/null 2>&1 && svpn_service firewall reload || exit 1
	fi
	if [ "$mode" = managed ]; then
		if [ "$direction" = after ] && [ "${reconnect:-0}" = 1 ]; then
			svpn_service openvpn stop svpn_client || exit 1
		fi
		svpn_service openvpn start svpn_client || exit 1
	fi
	if [ -n "$mode" ]; then
		attempt=0
		until svpn_vpn_ready "$meta" "$client" "$tun"; do
			if [ "$direction" = after ] && svpn_tx_expired; then exit 1; fi
			[ "$attempt" -lt 12 ] || { svpn_state_error 'The VPN did not become ready.'; exit 1; }
			sleep 1; attempt=$((attempt + 1))
		done
		if [ "$logical" = svpn_vpn ]; then svpn_vpn_attach "$id" "$logical" "$tun" || exit 1; fi
	fi
	if [ "$direction" = before ]; then running=$(svpn_state_read "$meta/pbr.before") || exit 1
	else
		svpn_resource_read option pbr.config.enabled "$meta/enabled" "$meta" || exit 1
		if grep -qx "[[:space:]]*option enabled '1'" "$meta/enabled"; then running=1; else running=0; fi
	fi
	case "$running" in 1) action=reload ;; 0) action=stop ;; *) exit 1 ;; esac
	if [ "$direction" = after ] && svpn_tx_expired; then exit 1; fi
	result=0
	if [ "$direction" = after ]; then svpn_state_mark "$meta/pbr.intent" 1 sync && sync || exit 1; fi
	svpn_pbr_reload "$meta" "$action" || result=1
	# restore forwarding even when PBR exits partway through a reload
	svpn_forward_restore "$meta" || result=1
	[ "$result" = 0 ] || exit 1
	if [ -n "$mode" ]; then svpn_pbr_ready "$meta" "$logical" "$tun" || exit 1
	elif [ "$running" = 1 ]; then svpn_pbr_health "$meta" && svpn_pbr_policies "$meta" || exit 1; fi
	if [ "$direction" = after ] && [ "$(svpn_state_read "$meta/dns")" = dnsmasq.nftset ]; then
		svpn_runtime_dns "$meta" || exit 1
	fi
	[ -n "$tun" ] || tun=svpn_absent
	svpn_runtime_check "$meta" "$tun" "$meta/eligible"
)

svpn_lifecycle_restore() (
	[ "$#" -eq 1 ] && svpn_tx_load "$1" && svpn_private_directory "$tx/lifecycle" || exit 1
	if [ "$(svpn_state_read "$tx/boot")" != "$(svpn_boot_id)" ]; then
		svpn_boot_resolver_restore "$tx/lifecycle"
		exit
	fi
	svpn_life_services "$1" before
)

svpn_lifecycle_stop_pending() (
	[ "$#" -eq 1 ] && svpn_tx_load "$1" && svpn_private_directory "$tx/lifecycle" || exit 1
	meta=$tx/lifecycle result=0
	if [ "$(svpn_state_read "$tx/boot")" != "$(svpn_boot_id)" ]; then
		svpn_state_mark "$meta/pbr.stopped" 1 sync
		exit
	fi
	# clean the native resolver while its applied settings are still present
	svpn_pbr_reload "$meta" stop || result=1
	svpn_forward_restore "$meta" || result=1
	[ "$result" = 0 ] && svpn_state_mark "$meta/pbr.stopped" 1 sync && sync
)

svpn_life_finish() (
	[ "$#" -eq 2 ] && svpn_tx_pending "$1" && svpn_private_directory "$2" || exit 1
	id=$1 work=$2
	if [ -e "$work/preserve_shared" ] && awk -F '\t' 'FILENAME ~ /pbr\.owned$/ { names[$1]=1; next }
		$1=="S" && $3 ~ /^(policy|dns_policy|include)$/ && !($4 in names) { found=1 }
		END { exit !found }' "$work/pbr.owned" "$work/pbr.table"; then
		for resource in "$work/wanted/option.pbr."*; do
			[ -e "$resource" ] || continue
			target=${resource##*/option.}
			if [ "$target" = pbr.config.supported_interface ] && [ -e "$work/restore_supported" ]; then continue; fi
			svpn_resource_read option "$target" "$work/current" "$work" || exit 1
			cp "$work/current" "$resource" || exit 1
		done
	fi
	if [ "${reconcile:-0}" = 1 ]; then
		unchanged=1
		for resource in "$work/wanted/"*; do
			[ -e "$resource" ] || continue
			name=${resource##*/}; kind=${name%%.*}; target=${name#*.}
			svpn_resource_read "$kind" "$target" "$work/current" "$work" || exit 1
			cmp -s "$resource" "$work/current" || unchanged=0
		done
	else unchanged=0; fi
	if [ "$unchanged" = 1 ]; then
		meta=$tx/lifecycle
		if svpn_vpn_ready "$meta" "$(svpn_state_read "$meta/after.client")" "$(svpn_state_read "$meta/after.device")" &&
			svpn_pbr_ready "$meta" "$(svpn_state_read "$meta/after.interface")" "$(svpn_state_read "$meta/after.device")" &&
			{ [ "$(svpn_state_read "$meta/dns")" != dnsmasq.nftset ] || svpn_runtime_dns "$meta"; }; then
			svpn_life_fingerprint "$meta" > "$work/fingerprint" &&
				svpn_state_put "$runtime/reconciled" < "$work/fingerprint" && svpn_transaction rollback "$id" || exit 1
			exit 0
		fi
	fi
	svpn_life_queue "$id" "$work" || { svpn_transaction rollback "$id"; exit 1; }
	svpn_transaction arm "$id" || { svpn_transaction rollback "$id"; exit 1; }
	# durable intent covers interruptions before the first service operation
	svpn_state_mark "$tx/lifecycle/intent" 1 sync && sync || exit 1
	if ! svpn_transaction apply "$id" || ! svpn_life_services "$id" after || ! svpn_transaction ready "$id"; then
		svpn_transaction rollback "$id" || :
		exit 1
	fi
	if [ "$unchanged" = 1 ]; then svpn_life_confirm "$id" || exit 1; fi
	svpn_life_fingerprint "$tx/lifecycle" > "$work/fingerprint" &&
		svpn_state_put "$runtime/reconciled" < "$work/fingerprint" || exit 1
	printf '%s\n' "$id"
)

# uses the saved draft rules, or the confirmed snapshot when svpn_rules=active
svpn_life_apply() (
	[ "$#" -eq 5 ] || exit 1
	mode=$1 selection=$2 networks=$3 ack=$4 peer=$5
	case "$mode" in managed|external) ;; *) exit 1 ;; esac
	[ "$ack" = 1 ] && svpn_valid_ipv4 "$peer" || {
		svpn_state_error 'Acknowledge the IPv4-only routing limitation before enabling.'; exit 1;
	}
	networks=$(svpn_normalize_list identifier "$networks") || exit 1
	runtime=$(svpn_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/lifecycle.XXXXXXXX") || exit 1
	network='' policy='' id=''
	trap '[ -z "$network" ] || svpn_network_discard "$network"; [ -z "$policy" ] || svpn_policy_discard "$policy"; rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/wanted" || exit 1
	svpn_life_preflight "$work" || exit 1
	network=$(svpn_network_prepare "$mode" "$selection" "$networks") || exit 1
	policy=$(svpn_policy_prepare "$network") || exit 1
	if [ -n "${svpn_review:-}" ]; then
		[ "$(svpn_routing_digest "$network" "$policy")" = "$svpn_review" ] || {
			svpn_state_error 'Routing inputs changed. Preview again before applying.'; exit 1;
		}
	fi
	# private copies retain only metadata needed for the lifecycle
	mkdir -m 700 "$work/network" "$work/policy" || exit 1
	for name in interface device client vpn_mode lan_subnets; do cp "$network/$name" "$work/network/$name" || exit 1; done
	svpn_state_mark "$work/network/mode" "$mode" && svpn_state_mark "$work/network/selection" "$selection" || exit 1
	cp "$policy/dns" "$work/policy/dns" && cp "$policy/pbr.table" "$work/pbr.table" || exit 1
	if [ "$(svpn_state_read "$policy/dns")" = dnsmasq.nftset ]; then
		for name in routers destinations; do cp "$policy/$name" "$work/policy/$name" || exit 1; done
		svpn_table_get "$policy/pbr.table" config resolver_instance | svpn_state_put "$work/policy/resolver_instance" || exit 1
	fi
	for resource in "$network/resources/"*; do
		[ -e "$resource" ] || continue
		svpn_life_want "$work" section "${resource##*/}" present < "$resource" || exit 1
	done
	for resource in "$policy/resources/"*; do
		[ -e "$resource" ] || continue
		cp "$resource" "$work/wanted/${resource##*/}" || exit 1
	done
	for row in "$policy/rules/"*; do
		svpn_life_want "$work" section "selective-vpn.svpn_rule_${row##*/}" present < "$row/active" || exit 1
	done
	# all interpolated values have already passed their list validators
	{
		printf "config settings 'svpn_active'\n\toption enabled '1'\n\toption mode '%s'\n\toption selection '%s'\n" "$mode" "$selection"
		printf "\toption networks '%s'\n\toption ipv6_acknowledged '1'\n" "$(printf '%s' "$networks" | tr '\n' ' ')"
	} | svpn_life_want "$work" section selective-vpn.svpn_active present || exit 1
	printf "\toption enabled '1'\n" | svpn_life_want "$work" option selective-vpn.main.enabled present || exit 1
	svpn_life_supported "$work" "$(svpn_state_read "$network/interface")" || exit 1
	svpn_life_obsolete "$work" apply || exit 1
	# unchanged events must not write another journal to flash
	if svpn_life_reconcile_ready "$work" "$network" "$policy"; then
		confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
		svpn_life_fingerprint "$tx/lifecycle" > "$work/fingerprint" &&
			svpn_state_put "$runtime/reconciled" < "$work/fingerprint" || exit 1
		exit 0
	fi
	id=$(svpn_transaction begin) || exit 1
	svpn_life_metadata "$id" "$work" "$peer" || { svpn_transaction rollback "$id"; exit 1; }
	# recheck live scope and private profile inputs immediately before arming
	svpn_discover_live "$work" > "$work/live.final" && cmp -s "$network/live" "$work/live.final" || {
		svpn_transaction rollback "$id"; exit 1;
	}
	svpn_network_recheck "$network" && svpn_policy_recheck "$policy" || {
		svpn_transaction rollback "$id"; exit 1;
	}
	svpn_life_finish "$id" "$work"
)

svpn_life_enable() (
	[ "$#" -eq 1 ] && svpn_valid_ipv4 "$1" || exit 1
	runtime=$(svpn_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/settings.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	svpn_life_active "$work" || exit 1
	svpn_rules=active
	svpn_life_apply "$(svpn_life_setting "$work" mode)" "$(svpn_life_setting "$work" selection)" \
		"$(svpn_life_setting "$work" networks)" "$(svpn_life_setting "$work" ipv6_acknowledged)" "$1"
)

svpn_life_reconnect() (
	[ "$#" -eq 1 ] && svpn_valid_ipv4 "$1" || exit 1
	runtime=$(svpn_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/reconnect.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	svpn_life_active "$work" || exit 1
	[ "$(svpn_table_get "$work/app.table" main enabled)" = 1 ] &&
		[ "$(svpn_life_setting "$work" mode)" = managed ] || exit 1
	# restart only the managed client, after the recovery journal is armed
	reconnect=1
	svpn_life_enable "$1"
)

svpn_life_remove() (
	[ "$#" -eq 2 ] && svpn_valid_ipv4 "$2" || exit 1
	mode=$1 peer=$2
	runtime=$(svpn_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/lifecycle.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	mkdir -m 700 "$work/wanted" || exit 1
	svpn_state_mark "$work/preserve_shared" 1 || exit 1
	svpn_life_preflight "$work" && svpn_life_active "$work" || exit 1
	cp "$SVPN_CONFIG_DIR/pbr" "$work/pbr.source" && chmod 600 "$work/pbr.source" || exit 1
	svpn_uci_export "$work/pbr.source" > "$work/pbr.export" || exit 1
	awk -v package=pbr -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/pbr.export" > "$work/pbr.table" || exit 1
	if [ "$mode" = rollback ]; then
		confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
		previous=$(svpn_state_read "$tx/previous") && svpn_tx_load "$previous" || {
			svpn_state_error 'There is no previous confirmed configuration.'; exit 1;
		}
		for record in "$tx/manifest/"*; do
			[ -e "$record" ] || continue
			svpn_tx_check_record "$record" || exit 1
			kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
			cp "$record/applied" "$work/wanted/$kind.$target" || exit 1
		done
		if [ -d "$tx/lifecycle" ]; then
			mkdir -m 700 "$work/network" || exit 1
			for key in mode selection interface device client; do cp "$tx/lifecycle/after.$key" "$work/network/$key" || exit 1; done
			cp "$tx/lifecycle/lan_subnets" "$work/network/lan_subnets" || exit 1
			mkdir -m 700 "$work/policy" || exit 1
			cp "$tx/lifecycle/dns" "$work/policy/dns" || exit 1
			if [ "$(svpn_state_read "$work/policy/dns")" = dnsmasq.nftset ]; then
				for name in routers destinations resolver_instance; do cp "$tx/lifecycle/$name" "$work/policy/$name" || exit 1; done
			fi
		fi
	elif [ "$mode" = disable ]; then
		svpn_uci_record selective-vpn.svpn_active read "$work/app.export" > "$work/active" || exit 1
		if [ -s "$work/active" ]; then
			awk '$0 !~ /^\toption enabled / { print }' "$work/active" > "$work/inactive" || exit 1
			printf "\toption enabled '0'\n" >> "$work/inactive"
			svpn_life_want "$work" section selective-vpn.svpn_active present < "$work/inactive" || exit 1
		fi
		printf "\toption enabled '0'\n" | svpn_life_want "$work" option selective-vpn.main.enabled present || exit 1
	fi
	svpn_life_obsolete "$work" "$mode" || exit 1
	id=$(svpn_transaction begin) || exit 1
	svpn_life_metadata "$id" "$work" "$peer" || { svpn_transaction rollback "$id"; exit 1; }
	svpn_life_finish "$id" "$work"
)

svpn_life_disable() { [ "$#" -eq 1 ] && svpn_life_remove disable "$1"; }
svpn_life_uninstall() { [ "$#" -eq 1 ] && svpn_life_remove uninstall "$1"; }
svpn_life_rollback() { [ "$#" -eq 1 ] && svpn_life_remove rollback "$1"; }

svpn_life_confirm() (
	[ "$#" -eq 1 ] && svpn_tx_pending "$1" && svpn_private_directory "$tx/lifecycle" || exit 1
	# repeat readiness checks before publishing the confirmed pointer
	meta=$tx/lifecycle
	mode=$(svpn_state_read "$meta/after.mode") && tun=$(svpn_state_read "$meta/after.device") || exit 1
	if [ -n "$mode" ]; then
		svpn_vpn_ready "$meta" "$(svpn_state_read "$meta/after.client")" "$tun" &&
			svpn_pbr_ready "$meta" "$(svpn_state_read "$meta/after.interface")" "$tun" || exit 1
	else
		svpn_resource_read option pbr.config.enabled "$meta/enabled" "$meta" || exit 1
		if grep -qx "[[:space:]]*option enabled '1'" "$meta/enabled"; then
			svpn_pbr_health "$meta" && svpn_pbr_policies "$meta" || exit 1
		elif svpn_service pbr running; then exit 1; fi
	fi
	if [ "$(svpn_state_read "$meta/dns")" = dnsmasq.nftset ]; then svpn_runtime_dns "$meta" || exit 1; fi
	[ -n "$tun" ] || tun=svpn_absent
	svpn_runtime_check "$meta" "$tun" "$meta/eligible" && svpn_transaction confirm "$1"
)

svpn_life_recover() { [ "$#" -eq 0 ] && svpn_transaction recover; }
svpn_life_boot() { [ "$#" -eq 0 ] && svpn_transaction recover; }

svpn_life_tick() (
	[ "$#" -eq 1 ] && svpn_state_id "$1" || exit 1
	svpn_tx_load "$1" || exit 1
	case "$(svpn_state_read "$tx/state")" in runtime_recovery) svpn_transaction recover ;; *) svpn_transaction tick "$1" ;; esac
)

svpn_life_event() (
	[ "$#" -eq 0 ] || exit 1
	[ ! -e "$SVPN_PRIVATE_DIR/pending" ] || exit 0
	[ -e "$SVPN_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	[ -d "$tx/lifecycle" ] || exit 0
	mode=$(svpn_state_read "$tx/lifecycle/after.mode") || exit 1
	[ -n "$mode" ] || exit 0
	peer=$(svpn_state_read "$tx/lifecycle/peer") || exit 1
	fingerprint=$(svpn_life_fingerprint "$tx/lifecycle") || exit 1
	if [ -e "$runtime/reconciled" ] && [ "$(svpn_state_read "$runtime/reconciled")" = "$fingerprint" ]; then exit 0; fi
	# regenerated scope always needs a new confirmation after a subnet change
	reconcile=1
	svpn_life_enable "$peer"
)

svpn_life_fingerprint() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	meta=$1
	runtime=$(svpn_runtime_directory) || exit 1
	work=$(mktemp -d "$runtime/fingerprint.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	{
		for package in selective-vpn network firewall openvpn pbr dhcp; do
			svpn_config_file "$SVPN_CONFIG_DIR/$package" || exit 1
			sha256sum "$SVPN_CONFIG_DIR/$package" || exit 1
		done
		svpn_discover_live "$work" > "$work/event.live" || exit 1
		sort "$work/event.live" || exit 1
		tun=$(svpn_state_read "$meta/after.device") || exit 1
		if [ -n "$tun" ]; then
			svpn_valid_netdev "$tun" || exit 1
			svpn_ip -4 -o address show dev "$tun" scope global 2>/dev/null || :
			ubus -t 5 call service list '{"name":"openvpn"}' > "$work/event.vpn" 2>/dev/null || exit 1
			[ "$(wc -c < "$work/event.vpn")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
			client=$(svpn_state_read "$meta/after.client") && svpn_valid_identifier "$client" || exit 1
			svpn_json_field "$work/event.vpn" "@.openvpn.instances.$client.running" || :
			svpn_json_field "$work/event.vpn" "@.openvpn.instances.$client.pid" || :
			logical=$(svpn_state_read "$meta/after.interface") && svpn_valid_interface "$logical" || exit 1
			svpn_config_file "$SVPN_RT_TABLES" || exit 1
			table=$(awk -v name="pbr_$logical" '$2==name && $1 ~ /^[0-9]+$/ { print $1 }' "$SVPN_RT_TABLES") || exit 1
			if svpn_valid_uint "$table" 999999999; then svpn_ip -4 route show table "$table" 2>/dev/null || :; fi
			svpn_ip -4 rule show 2>/dev/null || :
			if nft -j list chain inet fw4 pbr_prerouting > "$work/event.nft" 2>/dev/null; then
				[ "$(wc -c < "$work/event.nft")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
				svpn_json_field "$work/event.nft" '@.nftables[*].rule.comment' || :
			else printf '%s\n' missing_pbr_chain; fi
			if [ -f "$SVPN_PBR_DNS" ] && [ ! -L "$SVPN_PBR_DNS" ]; then
				[ "$(wc -c < "$SVPN_PBR_DNS")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] || exit 1
				sha256sum "$SVPN_PBR_DNS" || exit 1
			fi
		fi
	} > "$work/event.input" || exit 1
	sha256sum "$work/event.input" | cut -d ' ' -f 1
)
