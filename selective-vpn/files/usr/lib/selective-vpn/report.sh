#!/bin/sh

svpn_report_set() {
	printf '%s\t%s\n' "$1" "$2" >> "$report_work/fields"
}

svpn_report_program() (
	case "$1" in
		/*) [ -f "$1" ] && [ -x "$1" ] && printf '%s\n' "$1"; exit ;;
		''|*[!a-zA-Z0-9_-]*) exit 1 ;;
	esac
	# standalone BusyBox applets can hide an executable with the same name
	IFS=:
	set -f
	for directory in $PATH; do
		case "$directory" in /*) ;; *) continue ;; esac
		if [ -f "$directory/$1" ] && [ -x "$directory/$1" ]; then
			printf '%s\n' "$directory/$1"
			exit 0
		fi
	done
	exit 1
)

svpn_report_capture() (
	output=$1; shift
	timer=$(svpn_report_program timeout) || exit 1
	program=$(svpn_report_program "$1") || exit 1
	shift
	now=$(svpn_uptime)
	remaining=$((report_until - now))
	[ "$remaining" -gt 0 ] || exit 1
	[ "$remaining" -le 5 ] || remaining=5
	# bound both the wait and the amount kept from a native command
	{
		result=0
		"$timer" -s KILL "$remaining" "$program" "$@" 2>/dev/null || result=$?
		printf '%s\n' "$result" > "$output.result"
	} | head -c "$((SVPN_MAX_SNAPSHOT_BYTES + 1))" > "$output"
	[ "$(cat "$output.result")" = 0 ] && [ "$(wc -c < "$output")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ]
)

svpn_report() (
	[ "$#" -eq 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	case "$1" in status|doctor) ;; *) exit 1 ;; esac
	report=$1
	report_until=$(($(svpn_uptime) + 20))
	umask 077
	runtime=$(svpn_runtime_directory) && report_work=$(mktemp -d "$runtime/report.XXXXXXXX") || {
		awk -v report="$report" -f "$SVPN_LIBRARY_DIR/report-json.awk" /dev/null
		exit
	}
	trap 'rm -rf -- "$report_work"' EXIT
	trap 'exit 1' HUP INT TERM
	: > "$report_work/fields"
	for dependency in timeout ubus jsonfilter uci nft ss dnsmasq openvpn fw4 logread; do
		if svpn_report_program "$dependency" >/dev/null; then value=available; else value=missing; fi
		svpn_report_set "dependencies.$dependency" "$value"
	done
	if [ -x "$SVPN_IP" ]; then value=available; else value=missing; fi
	svpn_report_set dependencies.ip_full "$value"
	if [ -x "$SVPN_INIT_DIR/pbr" ]; then value=available; else value=missing; fi
	svpn_report_set dependencies.pbr "$value"
	lock_result=0
	svpn_report_lock || lock_result=$?
	if [ "$lock_result" -eq 0 ]; then
		svpn_report_set collection.state complete
		svpn_report_collect || svpn_report_set collection.state partial
	elif [ "$lock_result" -eq 4 ]; then
		svpn_report_set collection.state busy
	fi
	# the same allowlist protects interactive output and downloadable reports
	awk -v report="$report" -f "$SVPN_LIBRARY_DIR/report-json.awk" "$report_work/fields"
) 2>/dev/null

svpn_report_lock() {
	for name in lifecycle.lock lock; do
		if [ ! -e "$runtime/$name" ] && [ ! -L "$runtime/$name" ]; then
			(set -C; : > "$runtime/$name") 2>/dev/null || return 1
		fi
		svpn_private_file "$runtime/$name" || return 1
	done
	exec 8<> "$runtime/lifecycle.lock" || return 1
	flock -w 1 8 || return 4
	exec 9<> "$runtime/lock" || return 1
	flock -w 1 9 || return 4
}

svpn_report_collect() {
	partial=0
	enabled=unknown client='' tun='' logical='' policies=unknown
	if grep -q 'missing$' "$report_work/fields"; then partial=1; fi
	for package in selective-vpn network firewall openvpn pbr dhcp; do
		if ! svpn_report_config "$package"; then partial=1; fi
	done
	dirty=absent
	for package in selective-vpn network firewall openvpn pbr dhcp; do
		if [ -e "$SVPN_CONFIG_OVERRIDE_DIR/$package" ] || [ -L "$SVPN_CONFIG_OVERRIDE_DIR/$package" ]; then dirty=present
		elif changes=$(uci -q changes "$package"); then
			[ -z "$changes" ] || dirty=present
		elif [ "$dirty" != present ]; then dirty=unknown; fi
	done
	svpn_report_set configuration.pending_uci "$dirty"
	if [ -f "$report_work/selective-vpn.table" ]; then
		enabled=$(svpn_table_get "$report_work/selective-vpn.table" main enabled) || enabled=''
		svpn_report_bool configuration.enabled "$enabled"
		value=$(awk -F '\t' '$1 == "S" && $3 == "active_rule" { n++ } END { print n + 0 }' "$report_work/selective-vpn.table") &&
			svpn_report_set configuration.rules "$value"
	fi
	if svpn_report_capture "$report_work/supervisor.json" ubus -t 3 call service list '{"name":"selective-vpn"}'; then
		value=$(svpn_json_field "$report_work/supervisor.json" "@['selective-vpn'].instances.recovery.running") || value=''
		case "$value" in true) value=running ;; false) value=stopped ;; *) value=unknown ;; esac
		svpn_report_set recovery.supervisor "$value"
	fi
	svpn_report_journal || { report_meta=''; policies=unknown; partial=1; }
	svpn_report_routes
	svpn_report_pbr
	svpn_report_owned
	svpn_report_dns_capability
	if [ "$report" = status ]; then svpn_report_details; fi
	if [ -n "${report_meta:-}" ]; then
		svpn_report_identity && {
			svpn_report_vpn
			svpn_report_vpn_routes
			svpn_report_firewall
		} || partial=1
		svpn_report_policy_rules
		svpn_report_dns
		if [ "$report" = doctor ]; then svpn_report_baseline; fi
	fi
	if [ "$report" = doctor ]; then
		if svpn_report_capture "$report_work/firewall.check" fw4 check; then value=valid; else value=unknown; fi
		if [ -e "$report_work/firewall.check.result" ] && [ "$(cat "$report_work/firewall.check.result")" = 1 ]; then value=invalid; fi
		svpn_report_set firewall.candidate "$value"
		if svpn_report_capture "$report_work/logs" logread -l 200; then
			awk -f "$SVPN_LIBRARY_DIR/report-logs.awk" "$report_work/logs" >> "$report_work/fields" || return 1
			svpn_report_set logs.state summarized
		else svpn_report_set logs.state unavailable; fi
	fi
	[ "$partial" -eq 0 ] && [ "$(svpn_uptime)" -lt "$report_until" ]
}

svpn_report_bool() {
	case "$2" in 1) value=true ;; 0) value=false ;; *) value=null ;; esac
	svpn_report_set "$1" "$value"
}

svpn_report_config() (
	package=$1
	svpn_config_file "$SVPN_CONFIG_DIR/$package" || exit 1
	cp "$SVPN_CONFIG_DIR/$package" "$report_work/$package.source" || exit 1
	svpn_uci_export "$report_work/$package.source" > "$report_work/$package.export" || exit 1
	awk -v package="$package" -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$report_work/$package.export" > "$report_work/$package.table" || exit 1
)

svpn_report_journal() {
	report_meta=''
	if [ -e "$SVPN_PRIVATE_DIR/pending" ] || [ -L "$SVPN_PRIVATE_DIR/pending" ]; then pointer=pending
	elif [ -e "$SVPN_PRIVATE_DIR/confirmed" ] || [ -L "$SVPN_PRIVATE_DIR/confirmed" ]; then pointer=confirmed
	else svpn_report_set recovery.state none; return 0; fi
	id=$(svpn_tx_pointer "$pointer") && svpn_tx_load "$id" || return 1
	state=$(svpn_state_read "$tx/state") || return 1
	case "$state" in preparing|armed|applying|applied|awaiting_confirmation|confirmed|recovering|runtime_recovery|conflict|rolled_back) ;;
		*) return 1 ;;
	esac
	svpn_report_set recovery.state "$state"
	if [ "$pointer" = pending ] && [ "$(svpn_state_read "$tx/boot")" = "$(svpn_boot_id)" ]; then
		deadline=$(svpn_state_read "$tx/deadline") && svpn_valid_uint "$deadline" 999999999 || return 1
		now=$(svpn_uptime) && svpn_valid_uint "$now" 999999999 || return 1
		remaining=$((deadline - now))
		[ "$remaining" -ge 0 ] || remaining=0
		[ "$remaining" -le "$SVPN_CONFIRM_SECONDS" ] || return 1
		svpn_report_set recovery.seconds_remaining "$remaining"
	fi
	case "$state" in awaiting_confirmation|confirmed) ;; *) return 0 ;; esac
	svpn_private_directory "$tx/lifecycle" || return 1
	report_meta=$tx/lifecycle
	report_tx=$tx
	settings=match policies=match count=0
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		count=$((count + 1)); [ "$count" -le "$SVPN_MAX_RESOURCES" ] || return 1
		svpn_tx_check_record "$record" || return 1
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") && svpn_resource_target "$kind" "$target" || return 1
		[ "$kind" != file ] || continue
		package=${target%%.*}
		if [ ! -s "$report_work/$package.export" ]; then settings=unknown; policies=unknown; continue; fi
		svpn_uci_record "$target" read "$report_work/$package.export" > "$report_work/fragment" || return 1
		if [ -s "$report_work/fragment" ]; then
			{ printf 'present\n'; cat "$report_work/fragment"; } > "$report_work/current"
		else printf 'missing\n' > "$report_work/current"; fi
		if ! cmp -s "$record/applied" "$report_work/current"; then
			settings=changed
			case "$target" in pbr.*) policies=changed ;; esac
		fi
	done
	svpn_report_set configuration.owned_settings "$settings"
	svpn_report_set pbr.policy_configuration "$policies"
}

svpn_report_identity() {
	client=$(svpn_state_read "$report_meta/after.client") && tun=$(svpn_state_read "$report_meta/after.device") &&
		logical=$(svpn_state_read "$report_meta/after.interface") || return 1
	# disabled settings have no selected live tunnel
	[ -n "$client$tun$logical" ] || return 0
	svpn_valid_identifier "$client" && svpn_valid_netdev "$tun" && svpn_valid_interface "$logical"
}

# owned policies as id, label and section name, with ids like global or tv__preset
svpn_report_owned() {
	: > "$report_work/owned"
	[ -f "$report_work/pbr.table" ] || return 0
	awk -F '\t' '$1 == "S" { own[$2] = ($3 == "policy" && $4 ~ /^svpn_route_[a-zA-Z_][a-zA-Z0-9_]*$/); section[$2] = $4 }
		$1 == "V" && $3 == "name" { label[$2] = $4 }
		END { for (s in own) if (own[s] && label[s] ~ /^Selective VPN: [a-zA-Z0-9_ ]+$/)
			print substr(section[s], 12) "\t" label[s] "\t" section[s] }' "$report_work/pbr.table" |
		LC_ALL=C sort | head -n 128 > "$report_work/owned"
}

svpn_report_details() {
	tab=$(printf '\t')
	while IFS="$tab" read -r name label section; do
		[ "$(svpn_table_get "$report_work/pbr.table" "$section" enabled)" = 1 ] || continue
		sources=$(svpn_table_get "$report_work/pbr.table" "$section" src_addr) &&
			destinations=$(svpn_table_get "$report_work/pbr.table" "$section" dest_addr) &&
			protocols=$(svpn_table_get "$report_work/pbr.table" "$section" proto) &&
			ports=$(svpn_table_get "$report_work/pbr.table" "$section" dest_port) || continue
		sources=$(svpn_normalize_list destination "$sources") &&
			destinations=$(svpn_policy_destinations "$destinations") || continue
		[ -n "$sources" ] && [ -n "$destinations" ] || continue
		valid=1
		for source in $sources; do
			svpn_valid_ipv4 "$source" || { svpn_valid_subnet "$source" && [ "${source##*/}" -gt 0 ]; } || valid=0
		done
		for value in $protocols; do case "$value" in tcp|udp) ;; *) valid=0 ;; esac; done
		for value in $ports; do case "$value" in *[!0-9-]*) valid=0 ;; esac; done
		[ "$valid" = 1 ] || continue
		svpn_report_set "sources.$name" "$(printf '%s' "$sources" | tr '\n' ' ')"
		svpn_report_set "destinations.$name" "$(printf '%s' "$destinations" | tr '\n' ' ')"
		svpn_report_set "protocols.$name" "$protocols"
		svpn_report_set "ports.$name" "$ports"
	done < "$report_work/owned"
}

svpn_report_routes() {
	for family in 4 6; do
		case "$family" in 4) field=main_ipv4_default ;; 6) field=ipv6_default ;; esac
		if svpn_report_capture "$report_work/main$family" "$SVPN_IP" "-$family" -o route show table main; then
			if grep -q '^default ' "$report_work/main$family"; then value=present; else value=missing; fi
			svpn_report_set "routing.$field" "$value"
		fi
	done
}

svpn_report_vpn() {
	[ -n "$client" ] || return 0
	if [ "$report" = status ]; then svpn_report_set details.interface "$tun"; fi
	process=unknown ipv4=unknown
	if svpn_report_capture "$report_work/vpn.json" ubus -t 3 call service list '{"name":"openvpn"}'; then
		running=$(svpn_json_field "$report_work/vpn.json" "@.openvpn.instances.$client.running") || running=''
		case "$running" in
			false) process=stopped ;;
			true)
				process=unverified
				pid=$(svpn_json_field "$report_work/vpn.json" "@.openvpn.instances.$client.pid") || pid=''
				if svpn_valid_uint "$pid" 999999999 && [ "$pid" -gt 1 ] && kill -0 "$pid" &&
					[ "$(readlink "$SVPN_PROC_DIR/$pid/exe")" = /usr/sbin/openvpn ]; then
					tr '\000' '\n' < "$SVPN_PROC_DIR/$pid/cmdline" | head -c "$SVPN_MAX_SNAPSHOT_BYTES" > "$report_work/command"
					if awk -v tun="$tun" 'last == "--dev" && $0 == tun { found=1 } { last=$0 } END { exit !found }' "$report_work/command"; then
						process=running
					fi
				fi ;;
		esac
	fi
	svpn_report_set vpn.process "$process"
	# a client copied into a managed profile should no longer run
	replaced=none adopted=''
	[ ! -e "$report_meta/after.adopted" ] || adopted=$(svpn_state_read "$report_meta/after.adopted") || adopted=''
	if [ -n "$adopted" ]; then
		replaced=unknown
		if [ -f "$report_work/vpn.json" ] && svpn_valid_identifier "$adopted"; then
			case "$(svpn_json_field "$report_work/vpn.json" "@.openvpn.instances.$adopted.running" || :)" in
				true) replaced=running ;;
				*) replaced=stopped ;;
			esac
		fi
	fi
	svpn_report_set vpn.replaced_client "$replaced"
	svpn_report_set vpn.tunnel not_ready
	if svpn_report_capture "$report_work/address" "$SVPN_IP" -4 -o address show dev "$tun" scope global; then
		addresses=$(awk '$3 == "inet" {print $4}' "$report_work/address")
		value=missing
		for address in $addresses; do
			if ! svpn_valid_cidr "$address" || [ "${address##*/}" -lt 8 ]; then value=invalid; break; fi
			first=${address%%.*}
			if [ "$first" -eq 0 ] || [ "$first" -eq 127 ] || [ "$first" -ge 224 ]; then value=invalid; break; fi
			value=usable
		done
		ipv4=$value
		svpn_report_set vpn.ipv4 "$ipv4"
		if [ "$report" = status ] && [ "$ipv4" = usable ]; then
			addresses=$(svpn_normalize_list destination "$addresses") || addresses=''
			svpn_report_set details.addresses "$(printf '%s' "$addresses" | tr '\n' ' ')"
		fi
	fi
	flags=$(cat "$SVPN_SYS_CLASS_NET/$tun/tun_flags") || flags=''
	case "$flags" in 0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;; *) flags=0 ;; esac
	if [ "$process" = running ] && [ "$ipv4" = usable ] && [ "$((flags & 3))" -eq 1 ] &&
		svpn_report_capture "$report_work/link" "$SVPN_IP" -o link show dev "$tun" &&
		grep -Eq '<([^>]*,)?UP(,|>)' "$report_work/link"; then
		svpn_report_set vpn.tunnel ready
		svpn_report_set evidence.tunnel observed
	fi
	if svpn_report_capture "$report_work/logical.json" ubus -t 3 call "network.interface.$logical" status '{}'; then
		if [ "$(svpn_json_field "$report_work/logical.json" '@.up')" = true ] &&
			[ "$(svpn_json_field "$report_work/logical.json" '@.l3_device')" = "$tun" ]; then value=attached; else value=detached; fi
		svpn_report_set vpn.logical_interface "$value"
	fi
}

svpn_report_pbr() {
	if svpn_report_capture "$report_work/version" "$SVPN_INIT_DIR/pbr" version; then
		if grep -Eq '(^|[^0-9.])1\.2\.2([^0-9.]|$)' "$report_work/version"; then value=supported; else value=unsupported; fi
		svpn_report_set pbr.version "$value"
	fi
	if svpn_report_capture "$report_work/pbr.running" "$SVPN_INIT_DIR/pbr" running; then
		svpn_report_set pbr.service running
	elif [ -e "$report_work/pbr.running.result" ] && [ "$(cat "$report_work/pbr.running.result")" = 1 ]; then
		svpn_report_set pbr.service stopped
	fi
	if svpn_report_capture "$report_work/pbr.json" ubus -t 3 call service list '{"name":"pbr"}'; then
		gateways=$(svpn_json_field "$report_work/pbr.json" '@.pbr.instances.main.data.gateways[*].name') || gateways=''
		if [ -n "$gateways" ]; then
			errors=$(svpn_json_field "$report_work/pbr.json" '@.pbr.instances.main.data.errors[*].code') || errors=''
			if [ -n "$errors" ]; then value=present; else value=absent; fi
			svpn_report_set pbr.errors "$value"
		fi
	fi
}

svpn_report_vpn_routes() {
	[ -n "$logical" ] && svpn_config_file "$SVPN_RT_TABLES" || return 0
	table=$(awk -v name="pbr_$logical" '$2 == name && $1 ~ /^[0-9]+$/ { print $1; n++ } END { if(n!=1) exit 1 }' "$SVPN_RT_TABLES") &&
		svpn_valid_uint "$table" 999999999 && [ "$table" -gt 0 ] || return 0
	if svpn_report_capture "$report_work/vpn.routes" "$SVPN_IP" -4 route show table "$table"; then
		if awk -v tun="$tun" '$1=="default" { for(i=2;i<NF;i++) if($i=="dev" && $(i+1)==tun) n++ } END { exit(n!=1) }' "$report_work/vpn.routes"; then value=present; else value=missing; fi
		svpn_report_set routing.vpn_default "$value"
	fi
	if svpn_report_capture "$report_work/rules" "$SVPN_IP" -4 rule show; then
		if awk -v table="$table" -v name="pbr_$logical" '/fwmark/ { for(i=1;i<NF;i++) if($i=="lookup" && ($(i+1)==name || $(i+1)==table)) n++ } END { exit !n }' "$report_work/rules"; then value=present; else value=missing; fi
		svpn_report_set routing.mark_rule "$value"
	fi
}

svpn_report_policy_rules() {
	[ -f "$report_work/pbr.table" ] || return 0
	svpn_report_capture "$report_work/nft.json" nft -j list chain inet fw4 pbr_prerouting || return 0
	array=$(svpn_json_field "$report_work/nft.json" '@.nftables') || return 0
	case "$array" in \[*) ;; *) return 0 ;; esac
	svpn_json_field "$report_work/nft.json" '@.nftables[*].rule.comment' > "$report_work/comments" || :
	all=1 policy_observed=0
	tab=$(printf '\t')
	while IFS="$tab" read -r name label section; do
		if grep -qxF "$label" "$report_work/comments"; then value=present; else value=absent; all=0; fi
		svpn_report_set "policies.$name" "$value"
	done < "$report_work/owned"
	# comments locate native rules; they cannot establish ownership or egress
	if [ "$all" -eq 1 ] && [ -s "$report_work/owned" ] && [ "${policies:-unknown}" = match ] && [ "$enabled" = 1 ] && [ "$dirty" = absent ]; then
		svpn_report_set evidence.policy_rules observed
		policy_observed=1
	fi
	index=0
	: > "$report_work/counters"
	while [ "$index" -lt 512 ]; do
		base="@.nftables[$index]"
		object=$(svpn_json_field "$report_work/nft.json" "$base") || break
		[ -n "$object" ] || break
		comment=$(svpn_json_field "$report_work/nft.json" "$base.rule.comment") || comment=''
		name=$(awk -F '\t' -v label="$comment" '$2 == label { print $1; exit }' "$report_work/owned")
		[ -n "$name" ] || { index=$((index + 1)); continue; }
		for kind in packets bytes; do
			values=$(svpn_json_field "$report_work/nft.json" "$base.rule.expr[*].counter.$kind") || values=''
			case "$values" in ''|*[!0-9]*) values=unknown ;; esac
			printf '%s\t%s\t%s\n' "$name" "$kind" "$values" >> "$report_work/counters"
		done
		index=$((index + 1))
	done
	[ "$index" -lt 512 ] || return 0
	awk -F '\t' '
		NF==3 && $1 ~ /^[a-zA-Z_][a-zA-Z0-9_]*$/ && $2 ~ /^(packets|bytes)$/ {
			key=$2 "." $1
			if($3 !~ /^(0|[1-9][0-9]*)$/ || length($3)>15) bad[key]=1
			else { total[key]+=$3; seen[key]=1 }
		}
		END { for(key in seen) if(!bad[key] && total[key]<=999999999999999) {
			printf "%s\t%.0f\n", key, total[key]
			if(key ~ /^packets\./ && total[key]>0) matched=1
		} if(matched) print "matches\tobserved" }
	' "$report_work/counters" > "$report_work/safe.counters"
	awk -F '\t' '$1!="matches"' "$report_work/safe.counters" >> "$report_work/fields"
	if [ "$policy_observed" -eq 1 ] && grep -qx 'matches[[:space:]]observed' "$report_work/safe.counters"; then
		svpn_report_set evidence.policy_matches observed
	fi
}

svpn_report_dns_capability() {
	if svpn_report_capture "$report_work/dns.version" dnsmasq --version; then
		if awk '/^Compile time options:/ {for(i=4;i<=NF;i++) if($i=="nftset") found=1} END {exit !found}' "$report_work/dns.version"; then value=supported; else value=unsupported; fi
		svpn_report_set dns.nftset_capability "$value"
	fi
}

svpn_report_dns() {
	dns=$(svpn_state_read "$report_meta/dns") || return 0
	if [ "$dns" = not_required ]; then
		svpn_report_set dns.integration not_required
		svpn_report_set dns.population not_required
		return 0
	fi
	[ "$dns" = dnsmasq.nftset ] || return 0
	for name in routers destinations resolver_instance; do
		svpn_private_file "$report_meta/$name" && [ "$(wc -c < "$report_meta/$name")" -le "$SVPN_MAX_LIST_BYTES" ] &&
			cp "$report_meta/$name" "$report_work/$name" || return 0
	done
	if svpn_report_dns_native; then value=ready; else value=not_ready; fi
	svpn_report_set dns.integration "$value"
	[ "$value" = ready ] || return 0
	awk -v destinations="$report_work/domains" '
		FILENAME==destinations {wanted[$0]=1; next}
		/^nftset=\// { n=split($0,a,"/"); if(n!=3 || !(a[2] in wanted)) next
			n=split(a[3],b,/[, \t]+/); for(i=1;i<=n;i++) if(b[i] ~ /^4#inet#fw4#pbr_[a-zA-Z0-9_]+$/) {
				split(b[i],c,"#"); if(!seen[c[4]]++) print c[4]
			} }
	' "$report_work/domains" "$report_work/resolver.snippet" > "$report_work/sets"
	count=0 population=empty
	while IFS= read -r name; do
		count=$((count + 1)); [ "$count" -le 64 ] || return 0
		svpn_report_capture "$report_work/set.json" nft -j list set inet fw4 "$name" || return 0
		type=$(svpn_json_field "$report_work/set.json" '@.nftables[*].set.type') || return 0
		[ "$type" = ipv4_addr ] || return 0
		elements=$(svpn_json_field "$report_work/set.json" '@.nftables[*].set.elem[*]') || elements=''
		[ -z "$elements" ] || population=nonempty
	done < "$report_work/sets"
	[ "$count" -gt 0 ] || return 0
	svpn_report_set dns.sets "$count"
	svpn_report_set dns.population "$population"
}

svpn_report_dns_native() (
	ubus() { svpn_report_native ubus "$@"; }
	dnsmasq() { svpn_report_native dnsmasq "$@"; }
	ss() { svpn_report_native ss "$@"; }
	nft() { svpn_report_native nft "$@"; }
	svpn_runtime_dns "$report_work"
)

svpn_report_native() (
	case "$1" in ubus|dnsmasq|ss|nft) name=$1 ;; "$SVPN_IP") name=ip ;; *) exit 1 ;; esac
	svpn_report_capture "$report_work/native.$name" "$@" && cat "$report_work/native.$name"
)

svpn_report_firewall() {
	[ -n "$logical" ] && [ -f "$report_work/firewall.table" ] || return 0
	awk -F '\t' -v logical="$logical" -v tun="$tun" '
		$1=="S" {type[$2]=$3}
		$1=="V" {
			if($3=="network" || $3=="device") {
				n=split($4,a,/ +/)
				for(i=1;i<=n;i++) if(($3=="network" && a[i]==logical) || ($3=="device" && a[i]==tun)) selected[$2]=1
			}
			v[$2,$3]=$4
		}
		END {
			n=0
			for(id in selected) if(type[id]=="zone") {n++; zone=id}
			if(n!=1) {print "firewall.zone\t" (n ? "ambiguous" : "missing"); exit}
			print "firewall.zone\tfound"
			masq=v[zone,"masq"]; input=v[zone,"input"]; forward=v[zone,"forward"]
			print "firewall.masquerading\t" (masq=="1" ? "true" : (masq=="0" || masq=="" ? "false" : "null"))
			print "firewall.input_restricted\t" (input ~ /^(DROP|REJECT)$/ ? "true" : (input=="ACCEPT" ? "false" : "null"))
			print "firewall.forward_restricted\t" (forward ~ /^(DROP|REJECT)$/ ? "true" : (forward=="ACCEPT" ? "false" : "null"))
		}
	' "$report_work/firewall.table" >> "$report_work/fields"
}

svpn_report_baseline() {
	if [ "$(svpn_state_read "$report_tx/boot")" != "$(svpn_boot_id)" ]; then
		svpn_report_set routing.activation_baseline stale
		return 0
	fi
	mkdir -m 700 "$report_work/baseline" || return 0
	for name in routes4 routes6 management peer ipv4_ip_forward ipv6_conf_all_forwarding before.device eligible; do
		svpn_private_file "$report_meta/$name" && [ "$(wc -c < "$report_meta/$name")" -le "$SVPN_MAX_SNAPSHOT_BYTES" ] &&
			cp "$report_meta/$name" "$report_work/baseline/$name" || return 0
	done
	if [ -n "$tun" ] && svpn_report_baseline_check; then value=unchanged
	else value=changed; fi
	svpn_report_set routing.activation_baseline "$value"
}

svpn_report_baseline_check() (
	svpn_ip() { svpn_report_native "$SVPN_IP" "$@"; }
	svpn_runtime_check "$report_work/baseline" "$tun" "$report_work/baseline/eligible"
)
