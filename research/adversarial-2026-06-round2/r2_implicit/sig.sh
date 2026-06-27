#!/bin/zsh
/Users/zahary/m/dev/io-mon/build/bin/io-mon inspect "$1" 2>/dev/null \
 | grep -E '^#[0-9]+ (file-open|file-read|file-write|file-create|file-truncate|library-load|path-probe|rename|symlink|ipc-connect)' \
 | sed -E 's/^#[0-9]+ //; s/ pid=[0-9]+//; s/ tid=[0-9]+//; s/ result=[0-9-]+//' \
 | sort
