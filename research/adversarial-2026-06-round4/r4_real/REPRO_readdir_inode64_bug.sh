#!/usr/bin/env bash
# R4 headline finding: io-mon shim's readdir interpose returns legacy INODE32
# struct dirent to INODE64 callers -> every directory name loses its leading byte,
# the ".." entry is dropped, large dirs lose/corrupt many entries. Breaks CPython
# (cannot import 'encodings') and GNU coreutils ls. io-mon still reports mcComplete.
set -u
SHIM=/Users/zahary/m/dev/io-mon/build/lib/librepro_monitor_shim.dylib
CLANG=/nix/store/ywx0xix8cck7g3kvlnbh51lhwxh5xvqm-clang-21.1.7/bin/clang
PY=/nix/store/2djmffykchgm4q4j7ylv7xgkg441mp2j-python3-3.12.7/bin/python3.12
LS=/nix/store/1swaqmkr1329q50ky497sps80p16fn95-coreutils-9.8/bin/ls
ENC=/nix/store/2djmffykchgm4q4j7ylv7xgkg441mp2j-python3-3.12.7/lib/python3.12/encodings

cat > /tmp/r4_real/_dd.c <<'EOF'
#include <dirent.h>
#include <stdio.h>
int main(int c,char**v){DIR*d=opendir(v[1]);struct dirent*e;int n=0,k=0;
while((e=readdir(d))){n++;if(!__builtin_strcmp(e->d_name,"__init__.py"))k=1;}
printf("entries=%d saw__init__=%d\n",n,k);return 0;}
EOF
$CLANG /tmp/r4_real/_dd.c -o /tmp/r4_real/_dd

echo "## bare readdir(2):"
echo -n "  no shim: "; /tmp/r4_real/_dd "$ENC"
echo -n "  w/ shim: "; env DYLD_INSERT_LIBRARIES=$SHIM /tmp/r4_real/_dd "$ENC" 2>/dev/null | grep -v body-patch
echo "## coreutils ls (first 2 names):"
echo -n "  no shim: "; $LS "$ENC" | head -2 | tr '\n' ' '; echo
echo -n "  w/ shim: "; env DYLD_INSERT_LIBRARIES=$SHIM $LS "$ENC" 2>/dev/null | grep -v body-patch | head -2 | tr '\n' ' '; echo
echo "## CPython startup:"
echo -n "  no shim: "; $PY -c 'print("python OK")' 2>&1 | tail -1
echo -n "  w/ shim: "; env DYLD_INSERT_LIBRARIES=$SHIM $PY -c 'print("python OK")' 2>&1 | grep -iE 'encodings|OK' | tail -1
