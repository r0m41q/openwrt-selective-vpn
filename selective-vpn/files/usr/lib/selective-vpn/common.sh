#!/bin/sh

readonly SVPN_CONFIG='selective-vpn'
readonly SVPN_LIBRARY_DIR='/usr/lib/selective-vpn'
readonly SVPN_PRIVATE_DIR='/etc/selective-vpn'
readonly SVPN_PROFILE_DIR='/etc/openvpn/selective-vpn'
readonly SVPN_RUNTIME_DIR='/var/run/selective-vpn'
readonly SVPN_SECTION_PREFIX='svpn_'
readonly SVPN_MAX_PROFILE_BYTES=32768
readonly SVPN_MAX_LIST_BYTES=4096
readonly SVPN_MAX_LIST_ITEMS=64
readonly SVPN_CONFIRM_SECONDS=120
readonly SVPN_CONFIG_DIR='/etc/config'
readonly SVPN_CONFIG_OVERRIDE_DIR='/var/run/uci'
readonly SVPN_MAX_SNAPSHOT_BYTES=131072
readonly SVPN_MAX_STATE_BYTES=2097152
readonly SVPN_MAX_RESOURCES=64
readonly SVPN_LEASE_FILE='/tmp/dhcp.leases'
readonly SVPN_SYS_CLASS_NET='/sys/class/net'
readonly SVPN_OPENVPN_DIR='/etc/openvpn'
readonly SVPN_INIT_DIR='/etc/init.d'
readonly SVPN_PROC_DIR='/proc'
readonly SVPN_RT_TABLES='/etc/iproute2/rt_tables'
readonly SVPN_PBR_DNS='/var/run/pbr.dnsmasq'
readonly SVPN_IP='/usr/libexec/ip-full'
