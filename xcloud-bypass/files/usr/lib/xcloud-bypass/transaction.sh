#!/bin/sh

xcb_transaction() (
	[ "$#" -ge 1 ] && [ "$(id -u)" -eq 0 ] || exit 1
	operation=$1
	shift
	case "$operation" in begin|add|arm|apply|ready|confirm|rollback|recover|tick|prune) ;; *) exit 1 ;; esac
	umask 077
	runtime=$(xcb_runtime_directory) || exit 1
	xcb_make_private_directory "$XCB_PRIVATE_DIR" || exit 1
	xcb_make_private_directory "$XCB_PRIVATE_DIR/transactions" || exit 1
	if [ ! -e "$runtime/lock" ] && [ ! -L "$runtime/lock" ]; then
		(set -C; : > "$runtime/lock") 2>/dev/null || :
	fi
	xcb_private_file "$runtime/lock" || exit 1
	exec 9<> "$runtime/lock" || exit 1
	if [ "$operation" = tick ]; then flock -n 9 || exit 4
	else flock -w 3 9 || exit 4; fi
	"xcb_tx_$operation" "$@"
)

xcb_tx_pointer() (
	value=$(xcb_state_read "$XCB_PRIVATE_DIR/$1") || exit 1
	xcb_state_id "$value" || exit 1
	printf '%s\n' "$value"
)

xcb_tx_load() {
	[ "$#" -eq 1 ] && xcb_state_id "$1" || return 1
	tx=$XCB_PRIVATE_DIR/transactions/$1
	xcb_private_directory "$tx" && xcb_private_directory "$tx/changes" &&
		xcb_private_directory "$tx/manifest" && xcb_private_directory "$tx/work"
}

xcb_tx_pending() {
	[ "$(xcb_tx_pointer pending)" = "$1" ] && xcb_tx_load "$1"
}

xcb_tx_copy_record() (
	[ "$#" -eq 2 ] && xcb_private_directory "$1" && xcb_private_directory "$2" || exit 1
	for field in kind target original applied; do
		xcb_private_file "$1/$field" && xcb_state_put "$2/$field" < "$1/$field" || exit 1
	done
)

xcb_tx_key() {
	printf '%s\n%s\n' "$1" "$2" | sha256sum | cut -d ' ' -f 1
}

xcb_tx_check_record() (
	xcb_private_directory "$1" || exit 1
	for field in kind target original applied; do
		xcb_private_file "$1/$field" || exit 1
		[ "$(wc -c < "$1/$field")" -le "$((XCB_MAX_SNAPSHOT_BYTES + 8))" ] || exit 1
	done
)

xcb_tx_begin() (
	[ "$#" -eq 0 ] || exit 1
	if [ -e "$XCB_PRIVATE_DIR/pending" ] || [ -L "$XCB_PRIVATE_DIR/pending" ]; then
		xcb_state_error 'An unfinished change needs recovery first.'; exit 1
	fi
	xcb_tx_prune || exit 1
	xcb_state_budget "$XCB_PRIVATE_DIR" || exit 1
	id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || exit 1
	xcb_state_id "$id" || exit 1
	tx=$XCB_PRIVATE_DIR/transactions/$id
	mkdir -m 700 "$tx" || exit 1
	for directory in changes manifest work snapshots; do mkdir -m 700 "$tx/$directory" || exit 1; done
	xcb_state_mark "$tx/state" preparing || exit 1
	if [ -e "$XCB_PRIVATE_DIR/confirmed" ] || [ -L "$XCB_PRIVATE_DIR/confirmed" ]; then
		previous=$(xcb_tx_pointer confirmed) || exit 1
		xcb_tx_load "$previous" || exit 1
		previous_tx=$tx
		tx=$XCB_PRIVATE_DIR/transactions/$id
		xcb_state_mark "$tx/previous" "$previous" || exit 1
		for record in "$previous_tx/manifest"/*; do
			[ -e "$record" ] || continue
			key=${record##*/}
			case "$key" in *[!a-f0-9]*|'') exit 1 ;; esac
			[ "${#key}" -eq 64 ] || exit 1
			mkdir -m 700 "$tx/manifest/$key" || exit 1
			xcb_tx_copy_record "$record" "$tx/manifest/$key" || exit 1
		done
	fi
	xcb_state_budget "$XCB_PRIVATE_DIR" || exit 1
	xcb_state_mark "$XCB_PRIVATE_DIR/pending" "$id" sync || exit 1
	sync || exit 1
	printf '%s\n' "$id"
)

xcb_tx_add() (
	[ "$#" -eq 4 ] && xcb_tx_pending "$1" && xcb_resource_target "$2" "$3" || exit 1
	[ "$(xcb_state_read "$tx/state")" = preparing ] || exit 1
	[ ! -e "$tx/incomplete" ] && xcb_state_budget "$XCB_PRIVATE_DIR" || exit 1
	id=$1 kind=$2 target=$3 presence=$4
	case "$presence" in present|missing) ;; *) exit 1 ;; esac
	count=0
	for record in "$tx/changes"/*; do
		[ -e "$record" ] || continue
		count=$((count + 1))
		[ "$(xcb_state_read "$record/kind")" != "$kind" ] ||
			[ "$(xcb_state_read "$record/target")" != "$target" ] || exit 1
	done
	[ "$count" -lt "$XCB_MAX_RESOURCES" ] || exit 1
	stage=$(mktemp -d "$tx/work/record.XXXXXXXX") || exit 1
	trap 'rm -rf -- "$stage"' EXIT
	trap 'exit 1' HUP INT TERM
	xcb_state_mark "$stage/kind" "$kind" && xcb_state_mark "$stage/target" "$target" || exit 1
	{ printf '%s\n' "$presence"; head -c "$((XCB_MAX_SNAPSHOT_BYTES + 1))"; } > "$stage/applied" || exit 1
	[ "$(wc -c < "$stage/applied")" -le "$((XCB_MAX_SNAPSHOT_BYTES + ${#presence} + 1))" ] || exit 1
	if [ "$presence" = missing ]; then [ "$(wc -c < "$stage/applied")" -eq 8 ] || exit 1; fi
	xcb_resource_validate "$kind" "$target" "$stage/applied" "$tx/work" || exit 1
	xcb_resource_read "$kind" "$target" "$stage/original" "$tx/work" || exit 1
	key=$(xcb_tx_key "$kind" "$target") || exit 1
	owned=$tx/manifest/$key
	if [ -d "$owned" ]; then
		xcb_private_directory "$owned" && xcb_private_file "$owned/applied" || exit 1
		cmp -s "$owned/applied" "$stage/original" || {
			xcb_state_error 'A managed resource was edited outside the application.'; exit 1;
		}
		xcb_state_mark "$tx/incomplete" 1 || exit 1
	else
		if [ "$kind" = section ] && [ "$(head -n 1 "$stage/original")" != missing ]; then
			xcb_state_error 'The reserved section already exists and is not owned by this application.'; exit 1
		fi
		owned_count=0
		for entry in "$tx/manifest"/*; do
			[ -e "$entry" ] || continue
			owned_count=$((owned_count + 1))
		done
		[ "$owned_count" -lt "$XCB_MAX_RESOURCES" ] || exit 1
		xcb_state_mark "$tx/incomplete" 1 || exit 1
		mkdir -m 700 "$owned" || exit 1
		xcb_tx_copy_record "$stage" "$owned" || exit 1
	fi
	xcb_state_put "$owned/applied" < "$stage/applied" || exit 1
	if [ "$kind" != file ]; then
		package=${target%%.*}
		if [ ! -e "$tx/snapshots/$package" ]; then
			xcb_state_put "$tx/snapshots/$package" < "$XCB_CONFIG_DIR/$package" || exit 1
		fi
	fi
	xcb_state_budget "$XCB_PRIVATE_DIR" || exit 1
	number=$(printf '%02d' "$count")
	mv -- "$stage" "$tx/changes/$number" || exit 1
	rm -f -- "$tx/incomplete"
)

xcb_tx_expired() (
	boot=$(xcb_state_read "$tx/boot") || exit 0
	[ "$boot" = "$(xcb_boot_id)" ] || exit 0
	deadline=$(xcb_state_read "$tx/deadline") || exit 0
	xcb_valid_uint "$deadline" 999999999 || exit 0
	now=$(xcb_uptime) || exit 0
	xcb_valid_uint "$now" 999999999 || exit 0
	[ "$now" -ge "$deadline" ]
)

xcb_tx_arm() (
	[ "$#" -eq 1 ] && xcb_tx_pending "$1" || exit 1
	[ "$(xcb_state_read "$tx/state")" = preparing ] || exit 1
	[ ! -e "$tx/incomplete" ] || exit 1
	[ -d "$tx/changes/00" ] || exit 1
	command -v setsid >/dev/null 2>&1 || {
		xcb_state_error 'The setsid utility is required for automatic recovery.'; exit 1;
	}
	now=$(xcb_uptime) || exit 1
	xcb_valid_uint "$now" 999999879 || exit 1
	xcb_state_mark "$tx/boot" "$(xcb_boot_id)" || exit 1
	xcb_state_mark "$tx/deadline" "$((now + XCB_CONFIRM_SECONDS))" || exit 1
	xcb_state_mark "$tx/state" armed || exit 1
	sync || exit 1
	setsid /bin/sh "$XCB_LIBRARY_DIR/recovery-watch" "$1" 8>&- 9>&- </dev/null >/dev/null 2>&1 &
	attempt=0
	while [ "$attempt" -lt 3 ]; do
		if [ -f "$runtime/watch.$1" ]; then
			pid=$(xcb_state_read "$runtime/watch.$1") || exit 1
			xcb_valid_uint "$pid" 999999999 && kill -0 "$pid" 2>/dev/null && exit 0
		fi
		sleep 1
		attempt=$((attempt + 1))
	done
	xcb_state_error 'The recovery watchdog could not start.'
)

xcb_tx_apply() (
	[ "$#" -eq 1 ] && xcb_tx_pending "$1" || exit 1
	[ "$(xcb_state_read "$tx/state")" = armed ] || exit 1
	pid=$(xcb_state_read "$runtime/watch.$1") || exit 1
	xcb_valid_uint "$pid" 999999999 && kill -0 "$pid" 2>/dev/null || exit 1
	xcb_tx_expired && { xcb_tx_rollback "$1"; exit 1; }
	xcb_state_mark "$tx/state" applying || exit 1
	for record in "$tx/changes"/*; do
		xcb_tx_check_record "$record" || exit 1
		kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
		if xcb_tx_expired || ! xcb_state_mark "$record/intent" 1 || ! sync ||
			! xcb_resource_write "$kind" "$target" "$record/applied" "$record/original" "$tx/work"; then
			xcb_tx_rollback "$1" || :
			exit 1
		fi
	done
	if xcb_tx_expired; then xcb_tx_rollback "$1"; exit 1; fi
	xcb_state_mark "$tx/state" applied
)

xcb_tx_ready() (
	[ "$#" -eq 1 ] && xcb_tx_pending "$1" || exit 1
	[ "$(xcb_state_read "$tx/state")" = applied ] || exit 1
	if xcb_tx_expired; then xcb_tx_rollback "$1"; exit 1; fi
	xcb_state_mark "$tx/state" awaiting_confirmation
)

xcb_tx_confirm() (
	[ "$#" -eq 1 ] && xcb_tx_pending "$1" || exit 1
	[ "$(xcb_state_read "$tx/state")" = awaiting_confirmation ] || exit 1
	if xcb_tx_expired; then xcb_tx_rollback "$1"; exit 1; fi
	for record in "$tx/changes"/*; do
		xcb_tx_check_record "$record" || exit 1
		kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
		xcb_resource_read "$kind" "$target" "$tx/work/verify" "$tx/work" || exit 1
		cmp -s "$record/applied" "$tx/work/verify" || exit 1
	done
	if xcb_tx_expired; then xcb_tx_rollback "$1"; exit 1; fi
	xcb_state_mark "$tx/state" confirmed && sync || exit 1
	if xcb_tx_expired; then xcb_tx_rollback "$1"; exit 1; fi
	# publishing this pointer is the commit point
	xcb_state_mark "$XCB_PRIVATE_DIR/confirmed" "$1" sync && sync || exit 1
	rm -f -- "$XCB_PRIVATE_DIR/pending" "$runtime/watch.$1" || exit 1
	xcb_tx_prune
)

xcb_tx_rollback() (
	[ "$#" -eq 1 ] && xcb_tx_pending "$1" || exit 1
	conflict=0
	xcb_state_mark "$tx/state" recovering || exit 1
	if [ -e "$tx/lifecycle/pbr.intent" ] && [ ! -e "$tx/lifecycle/pbr.stopped" ]; then
		type xcb_lifecycle_stop_pending >/dev/null 2>&1 && xcb_lifecycle_stop_pending "$1" || {
			xcb_state_mark "$tx/state" runtime_recovery
			exit 1
		}
	fi
	# reverse the write order so dependent resources are removed first
	for number in $(ls -1 "$tx/changes" | sort -r); do
		case "$number" in [0-9][0-9]) ;; *) exit 1 ;; esac
		record=$tx/changes/$number
		xcb_tx_check_record "$record" || exit 1
		[ -e "$record/intent" ] || [ -L "$record/intent" ] || continue
		xcb_private_file "$record/intent" || exit 1
		kind=$(xcb_state_read "$record/kind") && target=$(xcb_state_read "$record/target") || exit 1
		if xcb_resource_read "$kind" "$target" "$tx/work/verify" "$tx/work"; then
			if cmp -s "$record/original" "$tx/work/verify"; then continue; fi
			if cmp -s "$record/applied" "$tx/work/verify" &&
				xcb_resource_write "$kind" "$target" "$record/original" "$record/applied" "$tx/work"; then
				continue
			fi
		fi
		conflict=1
		xcb_state_mark "$record/conflict" 1 || exit 1
	done
	if [ "$conflict" -ne 0 ]; then
		if [ -e "$tx/lifecycle/intent" ] && type xcb_forward_restore >/dev/null 2>&1; then
			xcb_forward_restore "$tx/lifecycle" || :
		fi
		xcb_state_mark "$tx/state" conflict || exit 1
		printf '%s\n' 'Recovery left conflicting edits untouched. Review the private journal before retrying.' >&2
		exit 2
	fi
	if [ -e "$tx/lifecycle/intent" ]; then
		type xcb_lifecycle_restore >/dev/null 2>&1 && xcb_lifecycle_restore "$1" || {
			xcb_state_mark "$tx/state" runtime_recovery
			exit 1
		}
	fi
	xcb_state_mark "$tx/state" rolled_back && sync || exit 1
	rm -f -- "$XCB_PRIVATE_DIR/pending" "$runtime/watch.$1"
)

xcb_tx_recover() (
	[ "$#" -eq 0 ] || exit 1
	if [ ! -e "$XCB_PRIVATE_DIR/pending" ] && [ ! -L "$XCB_PRIVATE_DIR/pending" ]; then exit 0; fi
	id=$(xcb_tx_pointer pending) || exit 1
	if [ -e "$XCB_PRIVATE_DIR/confirmed" ] && [ "$(xcb_tx_pointer confirmed)" = "$id" ]; then
		rm -f -- "$XCB_PRIVATE_DIR/pending" "$runtime/watch.$id"
	else
		xcb_tx_rollback "$id"
	fi
)

xcb_tx_tick() (
	[ "$#" -eq 1 ] && xcb_state_id "$1" || exit 1
	[ -e "$XCB_PRIVATE_DIR/pending" ] || exit 0
	[ "$(xcb_tx_pointer pending)" = "$1" ] || exit 0
	xcb_tx_load "$1" || exit 1
	if [ -e "$XCB_PRIVATE_DIR/confirmed" ] && [ "$(xcb_tx_pointer confirmed)" = "$1" ]; then
		xcb_tx_recover; exit
	fi
	case "$(xcb_state_read "$tx/state")" in conflict|rolled_back) exit 0 ;; esac
	if xcb_tx_expired; then xcb_tx_rollback "$1"; else exit 3; fi
)

xcb_tx_prune() (
	[ "$#" -eq 0 ] || exit 1
	confirmed=''
	previous=''
	pending=''
	if [ -e "$XCB_PRIVATE_DIR/confirmed" ]; then
		confirmed=$(xcb_tx_pointer confirmed) || exit 1
		xcb_tx_load "$confirmed" || exit 1
		if [ -e "$tx/previous" ]; then
			previous=$(xcb_state_read "$tx/previous") && xcb_state_id "$previous" || exit 1
		fi
	fi
	if [ -e "$XCB_PRIVATE_DIR/pending" ]; then pending=$(xcb_tx_pointer pending) || exit 1; fi
	for directory in "$XCB_PRIVATE_DIR/transactions"/*; do
		[ -e "$directory" ] || continue
		id=${directory##*/}
		xcb_state_id "$id" && xcb_private_directory "$directory" || exit 1
		case "$id" in "$confirmed"|"$previous"|"$pending") continue ;; esac
		rm -rf -- "$directory" || exit 1
	done
)
