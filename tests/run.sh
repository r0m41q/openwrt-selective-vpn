#!/bin/sh
set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
export PYTHONDONTWRITEBYTECODE=1

if [ -n "${XCB_TEST_SHELL:-}" ]; then
	python3 -m unittest discover -s "$test_dir" -p 'test_*.py' -v
	exit
fi

printf '%s\n' 'Testing with /bin/sh'
XCB_TEST_SHELL=/bin/sh python3 -m unittest discover -s "$test_dir" -p 'test_*.py' -v

if command -v busybox >/dev/null 2>&1; then
	printf '%s\n' 'Testing with BusyBox ash and tr'
	busybox_bin=$(command -v busybox)
	applet_dir=$(mktemp -d)
	trap 'rm -rf "$applet_dir"' EXIT
	trap 'exit 1' HUP INT TERM
	ln -s "$busybox_bin" "$applet_dir/tr"
	PATH="$applet_dir:$PATH" XCB_TEST_SHELL='busybox ash' \
		python3 -m unittest discover -s "$test_dir" -p 'test_*.py' -v
else
	printf '%s\n' 'BusyBox ash was not found; that check was skipped.'
fi
