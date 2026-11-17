#!/bin/sh
set -eu

# usage: sh tests/run.sh [test_module | test_module.Class.test_name ...]
test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
jobs=${SVPN_TEST_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}
export PYTHONDONTWRITEBYTECODE=1

if [ "$#" -eq 0 ]; then
	if command -v node >/dev/null 2>&1; then
		node --test "$test_dir/luci_test.cjs"
	else
		printf '%s\n' 'Node.js was not found; LuCI checks were skipped.'
	fi
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work_dir/logs" "$work_dir/applets"
export test_dir log_dir="$work_dir/logs" applet_dir="$work_dir/applets"

if [ -n "${SVPN_TEST_SHELL:-}" ]; then
	shells=env
else
	shells=sh
	if command -v busybox >/dev/null 2>&1; then
		shells='sh busybox'
		busybox_bin=$(command -v busybox)
		for applet in awk cat chmod cmp cp cut date df du grep head id ls mkdir mktemp mv od readlink rm rmdir sha256sum sleep sort stat sync tail timeout tr wc; do
			ln -s "$busybox_bin" "$applet_dir/$applet"
		done
	else
		printf '%s\n' 'BusyBox ash was not found; that check was skipped.'
	fi
fi

# every test runs in its own process so slow lifecycle cases spread across cores
(cd "$test_dir" && python3 - "$@") > "$work_dir/tests" <<'EOF'
import sys
import unittest

loader = unittest.TestLoader()
names = sys.argv[1:]
suite = loader.loadTestsFromNames(names) if names else loader.discover(".")


def walk(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from walk(test)
        else:
            yield test.id()


for name in walk(suite):
    print(name)
EOF

# start the slowest modules first
{
	grep -E '^test_(integration|lifecycle)\.' "$work_dir/tests" || :
	grep -vE '^test_(integration|lifecycle)\.' "$work_dir/tests" || :
} | while IFS= read -r name; do
	for shell in $shells; do printf '%s %s\n' "$shell" "$name"; done
done > "$work_dir/jobs"

printf 'Running %s tests with %s jobs\n' "$(wc -l < "$work_dir/jobs")" "$jobs"

job='
kind=$1 name=$2
case "$kind" in
	sh) shell=/bin/sh path=$PATH ;;
	busybox) shell="busybox ash" path=$applet_dir:$PATH ;;
	env) shell=$SVPN_TEST_SHELL path=$PATH ;;
esac
log=$log_dir/$kind.$name
if (cd "$test_dir" && PATH=$path SVPN_TEST_SHELL=$shell python3 -m unittest "$name") > "$log" 2>&1; then
	printf "ok    %-8s %s\n" "$kind" "$name"
else
	printf "FAIL  %-8s %s\n" "$kind" "$name"
	mv "$log" "$log.failed"
fi
'
xargs -n 2 -P "$jobs" sh -c "$job" job < "$work_dir/jobs"

failed=0
for log in "$log_dir"/*.failed; do
	[ -e "$log" ] || continue
	failed=$((failed + 1))
	printf '\n==== %s\n' "${log##*/}"
	cat "$log"
done
[ "$failed" -eq 0 ] || { printf '\n%s test runs failed\n' "$failed"; exit 1; }
printf '%s\n' 'All tests passed'
