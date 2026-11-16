#!/bin/sh

. /usr/lib/xcloud-bypass/common.sh
for library in validate private state transaction profile discover network policy runtime lifecycle report; do
	. "$XCB_LIBRARY_DIR/$library.sh"
done
