#!/bin/sh

# moving an existing OpenVPN client and hand-made PBR policies into the app

# the client's own config file, or one built from its UCI options
svpn_adopt_source() (
	[ "$#" -eq 2 ] && svpn_private_directory "$1" || exit 1
	work=$1 client=$2
	svpn_valid_identifier "$client" && ! svpn_reserved_identifier "$client" || exit 1
	svpn_config_file "$SVPN_CONFIG_DIR/openvpn" && svpn_uci_clean openvpn || exit 1
	cp -- "$SVPN_CONFIG_DIR/openvpn" "$work/openvpn.source" && chmod 600 "$work/openvpn.source" || exit 1
	svpn_uci_export "$work/openvpn.source" > "$work/openvpn.export" || exit 1
	awk -v package=openvpn -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/openvpn.export" > "$work/openvpn.table" || exit 1
	awk -F '\t' -v name="$client" '$1 == "S" && $3 == "openvpn" && $4 == name { found++ }
		END { exit (found != 1) }' "$work/openvpn.table" || { svpn_state_error 'The OpenVPN client was not found.'; exit 1; }
	path=$(svpn_table_get "$work/openvpn.table" "$client" config) || exit 1
	if [ -n "$path" ]; then
		svpn_config_file "$path" && [ "$(wc -c < "$path")" -le "$SVPN_MAX_PROFILE_BYTES" ] || {
			svpn_state_error 'The client configuration file is missing, unsafe or too large.'; exit 1;
		}
		cp -- "$path" "$work/client.conf" || exit 1
	else
		svpn_uci_record "openvpn.$client" read "$work/openvpn.export" > "$work/record" &&
			LC_ALL=C awk -v mode=uci -f "$SVPN_LIBRARY_DIR/adopt.awk" "$work/record" > "$work/client.conf" || {
			svpn_state_error 'The client options could not be converted.'; exit 1;
		}
	fi
	printf '%s\n' "$path" > "$work/path"
)

# a certificate, key or password file next to an existing client
svpn_adopt_file() (
	[ "$#" -eq 1 ] || exit 1
	case "$1" in /*) ;; *) exit 1 ;; esac
	case "$1" in *[!a-zA-Z0-9_./-]*|*/../*|*/./*|*/..|*/.) exit 1 ;; esac
	svpn_config_file "$1" && [ "$(wc -c < "$1")" -le 16384 ] || exit 1
	[ "$(LC_ALL=C tr -d '\11\12\15\40-\176' < "$1" | wc -c)" -eq 0 ]
)

# what keeps a client from being used as it is, one code and detail per line
svpn_client_check() (
	[ "$#" -eq 1 ] || exit 1
	client=$1
	runtime=$(svpn_runtime_directory) && work=$(mktemp -d "$runtime/client.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	svpn_adopt_source "$work" "$client" || exit 1
	get() { svpn_table_get "$work/openvpn.table" "$client" "$1"; }
	enabled=$(get enabled) && enable=$(get enable) && dev=$(get dev) && dev_type=$(get dev_type) &&
		security=$(get script_security) || exit 1
	{
		[ "$enabled" = 1 ] || [ "$enable" = 1 ] || printf 'disabled\t\n'
		path=$(cat "$work/path")
		[ -n "$path" ] || printf 'uci_only\t\n'
		hooks=0
		for hook in up down route_up route_pre_down ipchange; do
			value=$(get "$hook") || exit 1
			[ -z "$value" ] || hooks=1
		done
		case "$security" in ''|2|3) ;; *) hooks=1 ;; esac
		[ "$hooks" = 0 ] || printf 'hooks\t\n'
		LC_ALL=C awk -v mode=check -v dev="$dev" -v dev_type="$dev_type" -f "$SVPN_LIBRARY_DIR/adopt.awk" "$work/client.conf" || exit 1
	} > "$work/problems" || exit 1
	if [ ! -s "$work/problems" ]; then
		[ -n "$dev" ] || dev=$(svpn_vpn_file_device "$path") || exit 1
		LC_ALL=C awk -v mode=audit -v device="$dev" -v credentials="$work/credentials" \
			-v audit_external=1 -v references="$work/references" -v managed_credentials='' \
			-v audit_dev_type="$dev_type" -v output="$work/audited" -v summary="$work/summary" \
			-f "$SVPN_LIBRARY_DIR/profile.awk" "$work/client.conf" > /dev/null 2> "$work/audit" ||
			printf 'unsupported\t%s\n' "$(head -n 1 "$work/audit" | LC_ALL=C tr -cd ' -~' | cut -c 1-160)" > "$work/problems"
	fi
	cat "$work/problems"
)

# build a profile from an existing client and import it like an upload
svpn_profile_adopt() (
	[ "$#" -eq 2 ] && [ "$(id -u)" -eq 0 ] || exit 1
	client=$1 tun=$2
	runtime=$(svpn_runtime_directory) && work=$(mktemp -d "$runtime/adopt.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	svpn_adopt_source "$work" "$client" || exit 1
	LC_ALL=C awk -v mode=refs -v refs="$work/refs" -v credentials="$work/credentials" -v direction="$work/direction" \
		-f "$SVPN_LIBRARY_DIR/adopt.awk" "$work/client.conf" > "$work/assembled" || {
		svpn_state_error 'The client configuration could not be read.'; exit 1;
	}
	tab=$(printf '\t')
	while IFS="$tab" read -r name path direction; do
		svpn_adopt_file "$path" || { svpn_state_error 'A certificate or key file of the client is missing or unsafe.'; exit 1; }
		{ printf '<%s>\n' "$name"; awk '{ sub(/\r$/, ""); print }' "$path"; printf '</%s>\n' "$name"; } >> "$work/assembled" || exit 1
		if [ -n "$direction" ] && [ ! -s "$work/direction" ]; then
			printf 'key-direction %s\n' "$direction" >> "$work/assembled" && printf 1 > "$work/direction" || exit 1
		fi
	done < "$work/refs"
	bundle=$(svpn_profile_import "$tun" < "$work/assembled") || exit 1
	printf 'adopted_client=%s\n' "$client" >> "$bundle/summary" || exit 1
	path=$(head -n 1 "$work/credentials")
	# a password file that fails the checks is left for the user to enter in LuCI
	if [ -n "$path" ] && grep -qx 'auth_required=1' "$bundle/summary" && svpn_adopt_file "$path"; then
		awk '{ sub(/\r$/, ""); print }' "$path" | svpn_profile_credentials "$bundle" > /dev/null 2>&1 || :
	fi
	printf '%s\n' "$bundle"
)

# logical interfaces of the client being replaced, the only ones import accepts
svpn_pbr_interfaces() (
	[ "$#" -eq 3 ] && svpn_private_directory "$1" || exit 1
	work=$1 mode=$2 selection=$3 client=''
	case "$mode" in
		external) client=$selection ;;
		managed)
			printf '%s\n' "$selection" | grep -Eq '^profile\.[a-zA-Z0-9]{8}$' || exit 1
			client=$(svpn_adopted_client "$selection") || exit 1 ;;
		*) exit 1 ;;
	esac
	[ -n "$client" ] || exit 0
	svpn_valid_identifier "$client" && ! svpn_reserved_identifier "$client" || exit 1
	svpn_discover_configs "$work" || exit 1
	awk -F '\t' -v name="$client" '$1 == "S" && $3 == "openvpn" && $4 == name { found++ }
		END { exit (found != 1) }' "$work/openvpn.table" || exit 0
	dev=$(svpn_table_get "$work/openvpn.table" "$client" dev) || exit 1
	if [ -z "$dev" ]; then
		path=$(svpn_table_get "$work/openvpn.table" "$client" config) || exit 1
		[ -n "$path" ] && dev=$(svpn_vpn_file_device "$path" 2>/dev/null) || exit 0
	fi
	awk -F '\t' -v dev="$dev" '$1 == "S" { interface[$2] = ($3 == "interface" ? $4 : "") }
		$1 == "V" && ($3 == "device" || $3 == "ifname") && $4 == dev && interface[$2] != "" { print interface[$2] }' "$work/network.table"
)

# check every hand-made policy and turn the usable ones into converted lines
svpn_pbr_convert() (
	[ "$#" -eq 1 ] && svpn_private_directory "$1" || exit 1
	work=$1
	LC_ALL=C awk -v mode=scan -f "$SVPN_LIBRARY_DIR/pbr-import.awk" "$work/interfaces" "$work/pbr.table" > "$work/scan" || exit 1
	: > "$work/converted"
	: > "$work/report"
	mkdir -m 700 "$work/presets" || exit 1
	for preset in $(svpn_preset_catalog | cut -f 1); do
		mkdir -m 700 "$work/presets/$preset" && svpn_preset_load "$preset" "$work/presets/$preset" || exit 1
	done
	separator=$(printf '\037')
	while IFS="$separator" read -r index name label status address proto ports dests; do
		if [ "$status" = ok ]; then
			if ! dests=$(svpn_policy_destinations "$dests" 2>/dev/null); then status=destinations
			elif ! ports=$(svpn_rule_ports "$ports" 2>/dev/null); then status=ports
			fi
		fi
		if [ "$status" != ok ]; then
			printf '%s\t%s\t%s\t%s\t\n' "$index" "$name" "$label" "$status" >> "$work/report"
			continue
		fi
		dests=$(printf '%s\n' "$dests" | LC_ALL=C sort -u | tr '\n' ' ') && dests=${dests% }
		ports=$(printf '%s' "$ports" | tr '\n' ' ') && ports=${ports% }
		match=''
		for preset in "$work/presets/"*; do
			[ -d "$preset" ] || continue
			wanted=$(LC_ALL=C sort -u "$preset/destinations" | tr '\n' ' ') && wanted=${wanted% }
			[ "$wanted" = "$dests" ] && [ "$(cat "$preset/proto")" = "$proto " ] &&
				[ "$(cat "$preset/dest_port")" = "$ports" ] && match=${preset##*/} && break
		done
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$index" "$name" "$label" "$address" "$proto" "$ports" "$dests" "$match" >> "$work/converted"
	done < "$work/scan"
)

# report hand-made policies, or with save=1 turn them into draft rules
svpn_pbr_import() (
	[ "$#" -eq 3 ] || exit 1
	mode=$1 selection=$2 save=$3
	case "$save" in 0|1) ;; *) exit 1 ;; esac
	if [ "$save" = 1 ] && { [ -e "$SVPN_PRIVATE_DIR/pending" ] || [ -L "$SVPN_PRIVATE_DIR/pending" ]; }; then
		svpn_state_error 'Finish the pending change before importing policies.'; exit 1
	fi
	umask 077
	runtime=$(svpn_runtime_directory) && work=$(mktemp -d "$runtime/import.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$work"' EXIT
	trap 'exit 1' HUP INT TERM
	svpn_pbr_interfaces "$work" "$mode" "$selection" > "$work/interfaces" || exit 1
	path=$SVPN_CONFIG_DIR/pbr
	svpn_config_file "$path" && svpn_uci_clean pbr || exit 1
	cp -- "$path" "$work/pbr.source" && chmod 600 "$work/pbr.source" || exit 1
	svpn_uci_export "$work/pbr.source" > "$work/pbr.export" || exit 1
	awk -v package=pbr -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/pbr.export" > "$work/pbr.table" || exit 1
	svpn_pbr_convert "$work" || exit 1
	if [ "$save" = 1 ] && awk -F '\t' '$2 == "-" { found = 1 } END { exit !found }' "$work/converted"; then
		# PBR ignores section names, naming a policy only makes it trackable
		LC_ALL=C awk -F '\t' '
			$1 == "S" && $4 != "-" { used[$4] = 1 }
			FILENAME ~ /converted$/ && $2 == "-" {
				base = tolower($3); gsub(/[^a-z0-9]+/, "_", base); gsub(/^_+|_+$/, "", base)
				if (base !~ /^[a-z]/ || base ~ /^svpn_/) base = "policy" (base == "" ? "" : "_" base)
				base = substr(base, 1, 40); sub(/_+$/, "", base)
				name = base
				for (i = 2; name in used; i++) name = base "_" i
				used[name] = 1
				print $1 "\t" name
			}' "$work/pbr.table" "$work/converted" > "$work/rename" || exit 1
		LC_ALL=C awk -v mode=name -f "$SVPN_LIBRARY_DIR/pbr-import.awk" "$work/rename" "$work/pbr.export" > "$work/pbr.named" || exit 1
		svpn_uci_export "$work/pbr.named" > "$work/pbr.checked" &&
			awk -v package=pbr -f "$SVPN_LIBRARY_DIR/uci-inspect.awk" "$work/pbr.checked" > "$work/pbr.table" || exit 1
		mode_bits=$(stat -c '%a' "$path") || exit 1
		stage=$(mktemp "$SVPN_CONFIG_DIR/.selective-vpn.XXXXXXXX") || exit 1
		trap 'rm -f -- "$stage"; rm -rf -- "$work"' EXIT
		cat "$work/pbr.named" > "$stage" && chmod "$mode_bits" "$stage" && sync || exit 1
		svpn_uci_clean pbr && cmp -s "$path" "$work/pbr.source" || exit 1
		mv -f -- "$stage" "$path" || exit 1
		rm -rf -- "$work/presets" && svpn_pbr_convert "$work" || exit 1
	fi
	svpn_rules_draft "$work" > "$work/draft" && : > "$work/merged" || exit 1
	LC_ALL=C awk -v mode=merge -v out="$work/merged" -f "$SVPN_LIBRARY_DIR/pbr-import.awk" \
		"$work/draft" "$work/converted" > "$work/rules" || exit 1
	if [ "$save" = 1 ]; then
		mkdir -m 700 "$work/save" && svpn_rules_save "$work/save" < "$work/rules" || exit 1
	fi
	cat "$work/report" "$work/merged"
)
