#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -d "$1" ] || [ -L "$1" ]; then
	printf '%s\n' 'Usage: sh tests/openwrt-probe.sh EXISTING_OUTPUT_DIRECTORY' >&2
	exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
	printf '%s\n' 'Run this probe as root on the router.' >&2
	exit 1
fi
for program in mktemp timeout ubus ip nft uci apk fw4 xcloud-bypass; do
	if ! command -v "$program" >/dev/null 2>&1; then
		printf 'Missing command: %s\n' "$program" >&2
		exit 1
	fi
done

umask 077
output=$(mktemp -d "$1/probe.XXXXXXXX") || exit 1
printf 'UTC time: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$output/manifest.txt"

capture() {
	name=$1
	shift
	case "$name" in
		status.json|doctor.json) limit=25 ;;
		*) limit=10 ;;
	esac
	result=0
	timeout -s KILL "$limit" "$@" > "$output/$name" 2>&1 || result=$?
	printf '%s: %s\n' "$name" "$result" >> "$output/manifest.txt"
}

capture board.json ubus -t 5 call system board
capture packages.txt apk info -v xcloud-bypass luci-app-xcloud-bypass pbr openvpn-openssl dnsmasq-full
capture status.json xcloud-bypass status
capture doctor.json xcloud-bypass doctor
capture pbr-config.txt uci -q show pbr
capture app-config.txt uci -q show xcloud-bypass
capture ipv4-addresses.txt ip -4 -o address show
capture ipv4-main-routes.txt ip -4 -o route show table main
capture ipv4-all-routes.txt ip -4 -o route show table all
capture ipv4-rules.txt ip -4 rule show
capture ipv6-main-routes.txt ip -6 -o route show table main
capture ipv6-rules.txt ip -6 rule show
capture pbr-service.json ubus -t 5 call service list '{"name":"pbr"}'
capture openvpn-service.json ubus -t 5 call service list '{"name":"openvpn"}'
capture vpn-interface.json ubus -t 5 call network.interface.xcloud_vpn status
capture pbr-chain.txt nft -a list chain inet fw4 pbr_prerouting
capture pbr-sets.txt nft -a list sets inet fw4
capture firewall-check.txt fw4 check

printf 'Saved private router evidence in %s\n' "$output"
