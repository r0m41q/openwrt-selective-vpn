#!/bin/sh

readonly XCB_CONFIG='xcloud-bypass'
readonly XCB_LIBRARY_DIR='/usr/lib/xcloud-bypass'
readonly XCB_PRIVATE_DIR='/etc/xcloud-bypass'
readonly XCB_PROFILE_DIR='/etc/openvpn/xcloud-bypass'
readonly XCB_RUNTIME_DIR='/var/run/xcloud-bypass'
readonly XCB_SECTION_PREFIX='xcloud_'
readonly XCB_MAX_PROFILE_BYTES=32768
readonly XCB_MAX_LIST_BYTES=4096
readonly XCB_MAX_LIST_ITEMS=64
readonly XCB_CONFIRM_SECONDS=120
readonly XCB_CONFIG_DIR='/etc/config'
readonly XCB_CONFIG_OVERRIDE_DIR='/var/run/uci'
readonly XCB_MAX_SNAPSHOT_BYTES=131072
readonly XCB_MAX_STATE_BYTES=2097152
readonly XCB_MAX_RESOURCES=64
