#!/usr/bin/env bash
# Variables below are initialized by the pinned shared common.sh.
# shellcheck disable=SC2154,SC1091
set -euo pipefail
source "${RELEASE_TOOLS:?}/common.sh" "$@"
export STACKABLE_HOOKS_SRC="${RELEASE_STACKABLE_HOOKS_SRC:?}"
export SHM_QUEUE_SRC="${RELEASE_SHM_QUEUE_SRC:?}"
export SHM_GSET_SRC="${RELEASE_SHM_GSET_SRC:?}"
export IO_MON_BUILD_MODE=release IO_MON_TARGET_CPU="$release_cpu"
IO_MON_SHIM_NIMCACHE_DIR="$(pwd)/build/nimcache/release-$release_target"
export IO_MON_SHIM_NIMCACHE_DIR
bash scripts/build_shim.sh "${release_nim_flags[@]}"
nim c "${release_nim_flags[@]}" --nimcache:"build/nimcache/cli-$release_target" \
  --out:build/bin/io-mon cmd/io_mon_snoop.nim
cp build/bin/io-mon "$release_stage/bin/"
case "$release_os" in
  darwin) cp build/lib/librepro_monitor_shim.dylib "$release_stage/lib/" ;;
  linux) cp build/lib/librepro_monitor_shim.so "$release_stage/lib/" ;;
esac
cp LICENSE "$release_stage/"
nim c "${release_nim_flags[@]}" --nimcache:"build/nimcache/probe-$release_target" \
  --out:build/release-probe scripts/release/probe.nim
if [ "$release_os" = linux ]; then
  {
    file build/release-probe "$release_stage/bin/io-mon" "$release_stage/lib/librepro_monitor_shim.so"
    readelf -l -d build/release-probe
    readelf -d "$release_stage/lib/librepro_monitor_shim.so"
  } > test-logs/release-elf.txt
fi
RELEASE_SMOKE_PROBE="$(pwd)/build/release-probe"
export RELEASE_SMOKE_PROBE
release_finish
