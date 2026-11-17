#!/bin/sh

svpn_rule_ports() (
	[ "$#" -eq 1 ] && svpn_valid_size "$1" "$SVPN_MAX_LIST_BYTES" || exit 1
	set -f
	set -- $1
	[ "$#" -le "$SVPN_MAX_LIST_ITEMS" ] || exit 1
	result=''
	for port do
		case "$port" in
			*-*) first=${port%%-*}; last=${port#*-} ;;
			*) first=$port; last=$port ;;
		esac
		svpn_valid_uint "$first" 65535 && svpn_valid_uint "$last" 65535 &&
			[ "$first" -gt 0 ] && [ "$first" -le "$last" ] || exit 1
		result="$result$port
"
	done
	printf '%s' "$result" | LC_ALL=C sort -u
)

svpn_rule_proto() (
	[ "$#" -eq 1 ] || exit 1
	proto=$(svpn_normalize_list identifier "$1") || exit 1
	[ -n "$proto" ] || proto='tcp udp'
	for value in $proto; do case "$value" in tcp|udp) ;; *) exit 1 ;; esac; done
	printf '%s\n' "$proto" | tr '\n' ' '
)

# print one field of a shipped preset, fail for unknown ids
svpn_preset_field() (
	[ "$#" -eq 2 ] && svpn_valid_identifier "$1" && svpn_valid_identifier "$2" || exit 1
	LC_ALL=C awk -v id="$1" -v key="$2" '
		$1 == "preset" { current = $2; if (current == id) found = 1; next }
		current == id && $1 == key { sub(/^[ \t]*[^ \t]+[ \t]*/, ""); print }
		END { exit !found }' "$SVPN_LIBRARY_DIR/presets"
)

# presets get the same checks as rule rows
svpn_preset_load() (
	[ "$#" -eq 2 ] && svpn_private_directory "$2" || exit 1
	case "$1" in ''|*__*|*[!a-z0-9_]*|[!a-z]*) exit 1 ;; esac
	label=$(svpn_preset_field "$1" label) || { svpn_state_error "Unknown routing preset: $1"; exit 1; }
	proto=$(svpn_preset_field "$1" proto) && proto=$(svpn_rule_proto "$proto") &&
		ports=$(svpn_preset_field "$1" dest_port) && ports=$(svpn_rule_ports "$ports") &&
		destinations=$(svpn_preset_field "$1" destinations) &&
		destinations=$(svpn_policy_destinations "$destinations") &&
		warning=$(svpn_preset_field "$1" warning) || exit 1
	[ -n "$label" ] && [ -n "$destinations" ] || exit 1
	case "$warning" in ''|static_console_addresses_may_be_outdated) ;; *) exit 1 ;; esac
	printf '%s\n' "$label" > "$2/label" && printf '%s' "$proto" > "$2/proto" &&
		printf '%s' "$ports" | tr '\n' ' ' > "$2/dest_port" &&
		printf '%s\n' "$destinations" > "$2/destinations" || exit 1
	if [ -n "$warning" ]; then printf '%s\n' "$warning"; fi > "$2/warning"
)

svpn_rules_prepare() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" && svpn_private_directory "$2" || exit 1
	work=$1 network=$2
	svpn_config_file "$SVPN_CONFIG_DIR/selective-vpn" && svpn_uci_clean selective-vpn || exit 1
	cp "$SVPN_CONFIG_DIR/selective-vpn" "$work/app.source" || exit 1
	svpn_uci_export "$work/app.source" > "$work/app.export" || exit 1
	awk -v package=selective-vpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/app.export" > "$work/app.table" || exit 1
	type=rule
	[ "${svpn_rules:-}" != active ] || type=active_rule
	awk -F '\t' -v type="$type" '$1=="S" && $3==type {
		name=$4
		if(type=="active_rule") sub(/^svpn_rule_/,"",name)
		# a double underscore separates the rule from its preset in policy names
		if(name !~ /^[a-zA-Z_][a-zA-Z0-9_]*$/ || name ~ /__/ || length(name)>40 || ++count>24) exit 1
		if(name=="global") global++
		print name "\t" $4
	} END { if(global!=1) exit 1 }' "$work/app.table" > "$work/rows" || exit 1
	mkdir -m 700 "$work/rules" || exit 1
	: > "$work/devices"
	: > "$work/destinations"
	tab=$(printf '\t')
	while IFS="$tab" read -r name section; do
		row=$work/rules/$name
		mkdir -m 700 "$row" || exit 1
		for key in address proto dest_port destinations preset; do
			awk -F '\t' -v name="$section" -v key="$key" '
				$1=="S" && $4==name { s=$2 }
				$1=="V" && $2==s && $3==key { print $4 }' "$work/app.table" > "$row/$key.raw" || exit 1
		done
		address=$(cat "$row/address.raw") || exit 1
		if [ "$name" = global ]; then
			[ -z "$address" ] || exit 1
		else
			svpn_valid_ipv4 "$address" || exit 1
			! grep -qxF "$address" "$work/devices" || { svpn_state_error 'A device can only have one routing rule.'; exit 1; }
			printf '%s\n' "$address" >> "$work/devices"
			printf '%s\n' "$address" > "$row/sources"
		fi
		printf '%s\n' "$address" > "$row/address"
		svpn_rule_proto "$(cat "$row/proto.raw")" > "$row/proto" || exit 1
		ports=$(svpn_rule_ports "$(cat "$row/dest_port.raw")") || exit 1
		printf '%s' "$ports" | tr '\n' ' ' > "$row/dest_port"
		destinations=$(svpn_policy_destinations "$(cat "$row/destinations.raw")") || exit 1
		printf '%s\n' "$destinations" > "$row/destinations"
		printf '%s\n' "$destinations" >> "$work/destinations"
		presets=$(svpn_normalize_list identifier "$(cat "$row/preset.raw")") || exit 1
		mkdir -m 700 "$row/presets" || exit 1
		for preset in $presets; do
			mkdir -m 700 "$row/presets/$preset" && svpn_preset_load "$preset" "$row/presets/$preset" || exit 1
			cat "$row/presets/$preset/destinations" >> "$work/destinations" &&
				cat "$row/presets/$preset/warning" >> "$work/warnings" || exit 1
		done
		{
			printf "config active_rule 'svpn_rule_%s'\n" "$name"
			[ -z "$address" ] || printf "\toption address '%s'\n" "$address"
			printf "\toption proto '%s'\n\toption dest_port '%s'\n" "$(cat "$row/proto")" "$(cat "$row/dest_port")"
			for value in $destinations; do printf "\tlist destinations '%s'\n" "$value"; done
			for value in $presets; do printf "\tlist preset '%s'\n" "$value"; done
		} > "$row/active"
	done < "$work/rows"
	LC_ALL=C awk -v mode=scope -v scope=devices -f "$SVPN_LIBRARY_DIR/policy-check.awk" \
		"$work/devices" "$network/lan_subnets" "$network/live" || exit 1
	LC_ALL=C awk -f "$SVPN_LIBRARY_DIR/source-partition.awk" "$work/devices" "$network/lan_subnets" |
		LC_ALL=C sort -u > "$work/rules/global/sources" || exit 1
	for row in "$work/rules/"*; do
		sources=$(tr '\n' ' ' < "$row/sources") || exit 1
		svpn_valid_size "$sources" "$SVPN_MAX_LIST_BYTES" || { svpn_state_error 'The Global source partition is too large.'; exit 1; }
	done
	svpn_normalize_list destination "$(cat "$work/destinations")" > "$work/all.destinations" || exit 1
	mv "$work/all.destinations" "$work/destinations" || exit 1
)

svpn_rules_policy() (
	[ "$#" -eq 5 ] || exit 1
	work=$1 interface=$2 name=$3 sources=$4 row=$5
	[ -n "$(cat "$row/destinations")" ] || exit 0
	dest=$(tr '\n' ' ' < "$row/destinations") && proto=$(cat "$row/proto") && ports=$(cat "$row/dest_port") || exit 1
	target=pbr.svpn_route_$name
	svpn_resource_read section "$target" "$work/current" "$work" || exit 1
	if [ "$(head -n 1 "$work/current")" = present ]; then
		confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
		key=$(svpn_tx_key section "$target") || exit 1
		svpn_private_file "$tx/manifest/$key/applied" && cmp -s "$tx/manifest/$key/applied" "$work/current" || exit 1
	fi
	case "$name" in *__*) label="${name%%__*} ${name#*__}" ;; *) label=$name ;; esac
	svpn_policy_section "svpn_route_$name" "Selective VPN: $label" "$interface" "$sources" "${dest% }" "${proto% }" "$ports" > "$work/fragment" || exit 1
	svpn_policy_resource "$work" section "$target" present < "$work/fragment"
)

# each preset keeps its own protocol and ports in a separate policy
svpn_rules_policies() (
	[ "$#" -eq 2 ] || exit 1
	work=$1 interface=$2
	for row in "$work/rules/"*; do
		name=${row##*/}
		sources=$(tr '\n' ' ' < "$row/sources") || exit 1
		[ -n "$sources" ] || continue
		svpn_rules_policy "$work" "$interface" "$name" "${sources% }" "$row" || exit 1
		for preset in "$row/presets/"*; do
			[ -d "$preset" ] || continue
			svpn_rules_policy "$work" "$interface" "${name}__${preset##*/}" "${sources% }" "$preset" || exit 1
		done
	done
	[ -e "$SVPN_PRIVATE_DIR/confirmed" ] || exit 0
	confirmed=$(svpn_tx_pointer confirmed) && svpn_tx_load "$confirmed" || exit 1
	for record in "$tx/manifest/"*; do
		[ -e "$record" ] || continue
		kind=$(svpn_state_read "$record/kind") && target=$(svpn_state_read "$record/target") || exit 1
		case "$kind:$target" in section:pbr.svpn_route_*) ;; *) continue ;; esac
		[ ! -e "$work/resources/section.$target" ] || continue
		svpn_policy_resource "$work" section "$target" missing < /dev/null || exit 1
	done
)

# id, label and warning of every shipped preset
svpn_preset_catalog() (
	[ "$#" -eq 0 ] || exit 1
	LC_ALL=C awk '
		function flush() { if (id != "") print id "\t" v["label"] "\t" v["warning"] }
		$1 == "preset" { flush(); id = $2; split("", v); next }
		id != "" && ($1 == "label" || $1 == "warning") { key = $1; sub(/^[ \t]*[^ \t]+[ \t]*/, ""); v[key] = $0 }
		END { flush() }' "$SVPN_LIBRARY_DIR/presets"
)

# draft rows in the same text form that svpn_rules_save reads, global first
svpn_rules_draft() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	svpn_config_file "$SVPN_CONFIG_DIR/selective-vpn" && svpn_uci_clean selective-vpn || exit 1
	cp "$SVPN_CONFIG_DIR/selective-vpn" "$1/draft.source" || exit 1
	svpn_uci_export "$1/draft.source" > "$1/draft.export" || exit 1
	awk -v package=selective-vpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$1/draft.export" > "$1/draft.table" || exit 1
	LC_ALL=C awk -F '\t' '
		$1 == "S" { if ($3 == "rule" && $4 != "-") { row[$2] = $4; order[++n] = $4 } }
		$1 == "V" && ($2 in row) && $3 ~ /^(address|proto|dest_port|destinations|preset)$/ {
			key = row[$2] SUBSEP $3
			value[key] = value[key] == "" ? $4 : value[key] " " $4
		}
		function show(name,    i, k) {
			print "rule " name
			split("address proto dest_port destinations preset", keys, " ")
			for (i = 1; i <= 5; i++) {
				k = name SUBSEP keys[i]
				if (value[k] != "") print keys[i] " " value[k]
			}
		}
		END {
			for (i = 1; i <= n; i++) if (order[i] == "global") show(order[i])
			for (i = 1; i <= n; i++) if (order[i] != "global") show(order[i])
		}' "$1/draft.table"
)

# replace the draft rows from stdin, live routing only changes on apply
svpn_rules_save() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1
	if [ -e "$SVPN_PRIVATE_DIR/pending" ] || [ -L "$SVPN_PRIVATE_DIR/pending" ]; then
		svpn_state_error 'Finish the pending change before editing rules.'; exit 1
	fi
	head -c 32769 > "$work/save.input" && [ "$(wc -c < "$work/save.input")" -le 32768 ] || exit 1
	mkdir -m 700 "$work/save" || exit 1
	count=$(LC_ALL=C awk -v dir="$work/save" '
		function fail() { bad = 1; exit 1 }
		NF == 0 { next }
		$0 !~ /^[a-zA-Z0-9_. \/:-]*$/ { fail() }
		$1 == "rule" { if (NF != 2 || seen[$2]++ || ++rows > 24) fail(); split("", got); next }
		{
			if (!rows || $1 !~ /^(address|proto|dest_port|destinations|preset)$/ || got[$1]++) fail()
			value = $0
			sub(/^[ \t]*[^ \t]+[ \t]*/, "", value)
			print value > (dir "/" rows "." $1)
			close(dir "/" rows "." $1)
		}
		END { if (bad || !rows) exit 1; print rows }' "$work/save.input") || exit 1
	LC_ALL=C awk '$1 == "rule" { print $2 }' "$work/save.input" > "$work/save/names" || exit 1
	field() { if [ -e "$work/save/$1.$2" ]; then cat "$work/save/$1.$2"; fi; }
	i=0 global=0
	: > "$work/save/addresses"
	: > "$work/save/rules"
	while IFS= read -r name; do
		i=$((i + 1))
		case "$name" in ''|*__*|svpn_*|[!a-zA-Z_]*|*[!a-zA-Z0-9_]*) svpn_state_error "Invalid rule name: $name"; exit 1 ;; esac
		[ "${#name}" -le 40 ] || exit 1
		address=$(field "$i" address) || exit 1
		if [ "$name" = global ]; then
			global=1
			[ -z "$address" ] || exit 1
		else
			svpn_valid_ipv4 "$address" || { svpn_state_error "Invalid device address in rule $name."; exit 1; }
			! grep -qxF "$address" "$work/save/addresses" || { svpn_state_error 'A device can only have one routing rule.'; exit 1; }
			printf '%s\n' "$address" >> "$work/save/addresses"
		fi
		proto=$(svpn_rule_proto "$(field "$i" proto)") &&
			ports=$(svpn_rule_ports "$(field "$i" dest_port)") &&
			destinations=$(svpn_policy_destinations "$(field "$i" destinations)") &&
			presets=$(svpn_normalize_list identifier "$(field "$i" preset)") || {
			svpn_state_error "Invalid protocols, ports or destinations in rule $name."; exit 1;
		}
		for preset in $presets; do
			svpn_preset_field "$preset" label > /dev/null || { svpn_state_error "Unknown routing preset: $preset"; exit 1; }
		done
		{
			printf "config rule '%s'\n" "$name"
			[ -z "$address" ] || printf "\toption address '%s'\n" "$address"
			printf "\toption proto '%s'\n" "${proto% }"
			ports=$(printf '%s' "$ports" | tr '\n' ' ')
			[ -z "$ports" ] || printf "\toption dest_port '%s'\n" "${ports% }"
			for value in $destinations; do printf "\tlist destinations '%s'\n" "$value"; done
			for value in $presets; do printf "\tlist preset '%s'\n" "$value"; done
		} >> "$work/save/rules"
	done < "$work/save/names"
	[ "$i" -eq "$count" ] && [ "$global" = 1 ] || { svpn_state_error 'The Global rule is required.'; exit 1; }
	path=$SVPN_CONFIG_DIR/selective-vpn
	svpn_config_file "$path" && svpn_uci_clean selective-vpn || exit 1
	cp "$path" "$work/save/source" && chmod 600 "$work/save/source" || exit 1
	svpn_uci_export "$work/save/source" > "$work/save/export" || exit 1
	awk -v package=selective-vpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/save/export" > "$work/save/table" || exit 1
	# keep every other section as it is and replace the rule rows only
	awk -F '\t' '$1 == "S" && $3 == "rule" { if ($4 == "-") exit 1; print $4 }' "$work/save/table" > "$work/save/old" || exit 1
	# drop the package header like svpn_uci_record does so repeated saves match
	awk 'NR == 1 && $1 == "package" { header = 1; next } header && NR == 2 && $0 == "" { next } { print }' \
		"$work/save/export" > "$work/save/candidate" || exit 1
	while IFS= read -r old; do
		svpn_uci_record "selective-vpn.$old" replace "$work/save/candidate" /dev/null > "$work/save/next" &&
			mv "$work/save/next" "$work/save/candidate" || exit 1
	done < "$work/save/old"
	cat "$work/save/rules" >> "$work/save/candidate" || exit 1
	svpn_uci_export "$work/save/candidate" > "$work/save/checked" &&
		awk -v package=selective-vpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/save/checked" > /dev/null || {
		svpn_state_error 'A rule name is already used by another section.'; exit 1;
	}
	! cmp -s "$work/save/candidate" "$path" || exit 0
	mode=$(stat -c '%a' "$path") || exit 1
	stage=$(mktemp "$SVPN_CONFIG_DIR/.selective-vpn.XXXXXXXX") || exit 1
	trap 'rm -f -- "$stage"' EXIT
	trap 'exit 1' HUP INT TERM
	cat "$work/save/candidate" > "$stage" && chmod "$mode" "$stage" && sync || exit 1
	svpn_uci_clean selective-vpn && cmp -s "$path" "$work/save/source" || exit 1
	mv -f -- "$stage" "$path"
)
