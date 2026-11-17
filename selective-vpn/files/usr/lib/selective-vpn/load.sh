#!/bin/sh

. /usr/lib/selective-vpn/common.sh
for library in validate private state transaction profile discover network policy routing runtime lifecycle report; do
	. "$SVPN_LIBRARY_DIR/$library.sh"
done
