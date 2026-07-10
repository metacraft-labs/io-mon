#!/usr/bin/env bash
# Repeatable benchmark for the LD_PRELOAD monitor-shim overhead on a
# BEAM/Elixir-style workload (FUP-K).
#
# The BEAM VM's dominant monitored-syscall pattern is an enormous volume of
# small read()/write() on NON-INHERITED sockets/pipes ("ports"), none of which
# names a file. This benchmark reproduces that pattern with a tiny C program and
# measures the monitored wall-time, the total RMDF record count, and the
# DEP-SHM ring-full fallback rate — the three quantities FUP-K reduced.
#
# Usage:
#   scripts/bench_beam_overhead.sh [ITERS] [RUNS]
# Env:
#   REPRO_MONITOR_SHIM_LIB  pin a specific shim .so (else uses build/lib-release)
#
# Requires: a release shim (build via
#   IO_MON_BUILD_MODE=release IO_MON_SHIM_OUT_DIR=build/lib-release \
#     IO_MON_SHIM_NIMCACHE_DIR=build/nimcache-release scripts/build_shim.sh)
# and the io-mon CLI at build/bin/io-mon.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
ITERS="${1:-200000}"
RUNS="${2:-5}"
CLI="build/bin/io-mon"
SHIM="${REPRO_MONITOR_SHIM_LIB:-$here/build/lib-release/librepro_monitor_shim.so}"

[ -x "$CLI" ]   || { echo "missing $CLI; build the CLI first (see docs/contributors/building-and-testing.md)" >&2; exit 2; }
[ -f "$SHIM" ]  || { echo "missing shim $SHIM; build the release shim first" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/beamlike.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
int main(int argc, char **argv){
  long iters = (argc>1)?atol(argv[1]):200000;
  char buf[64]; memset(buf,'x',sizeof(buf));
  int sv[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)){perror("socketpair");return 1;}
  int pp[2]; if(pipe(pp)){perror("pipe");return 1;}
  for(int r=0;r<8;r++){int fd=open("/etc/hostname",O_RDONLY);if(fd>=0){char fb[256];ssize_t n=read(fd,fb,sizeof(fb));(void)n;close(fd);}}
  for(long i=0;i<iters;i++){
    ssize_t w=write(sv[0],buf,16);(void)w; ssize_t r=read(sv[1],buf,16);(void)r;
    ssize_t w2=write(pp[1],buf,16);(void)w2; ssize_t r2=read(pp[0],buf,16);(void)r2;
  }
  close(sv[0]);close(sv[1]);close(pp[0]);close(pp[1]);
  return 0;
}
EOF
cc -O2 -o "$work/beamlike" "$work/beamlike.c"

timeit(){ python3 - "$@" <<'PY'
import subprocess,time,sys
s=time.time(); subprocess.run(sys.argv[1:],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print("%.3f"%(time.time()-s))
PY
}
median(){ python3 -c "import sys;v=sorted(float(x) for x in sys.stdin.read().split());print('%.3f'%v[len(v)//2])"; }

echo "iters=$ITERS runs=$RUNS shim=$SHIM"
NAT=$(for i in $(seq "$RUNS"); do timeit "$work/beamlike" "$ITERS"; done | median)
MON=$(for i in $(seq "$RUNS"); do REPRO_MONITOR_SHIM_LIB="$SHIM" timeit "$CLI" run --depfile "$work/out.rdep" -- "$work/beamlike" "$ITERS"; done | median)
echo "native    median = ${NAT}s"
echo "monitored median = ${MON}s   (multiplier: $(python3 -c "print('%.1fx'%($MON/$NAT))"))"

# One extra monitored run to read the record count and ring-full fallback rate.
REPRO_MONITOR_SHIM_LIB="$SHIM" "$CLI" run --depfile "$work/out.rdep" -- "$work/beamlike" "$ITERS" 2>"$work/err" >/dev/null || true
echo -n "RMDF: "; "$CLI" inspect "$work/out.rdep" 2>/dev/null | head -1
echo -n "ring-full drops: "; grep -oi "[0-9]* record(s) fell back" "$work/err" || echo "0 (none)"
