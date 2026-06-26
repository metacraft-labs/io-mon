#!/usr/bin/env bash
# Build the io-mon interpose shim shared library.
#
# This is the RELOCATED counterpart of reprobuild's
# scripts/build_apps.sh shim section. It produces a shared library named
# `librepro_monitor_shim.{dylib,so,dll}` — the name is kept BYTE-IDENTICAL
# to reprobuild's historical shim so the M7 swap is drop-in: every consumer
# that locates the shim by that filename (including io-mon's own
# `fs_snoop.findShimLibrary`) keeps working unchanged.
#
# The shim's interpose ABI (the exported `repro_monitor_shim_*` /
# `repro_hook_*` / `repro_macos_*` / `ct_linux_preload_*` symbols and, on
# macOS, the `__DATA,__interpose` section) is preserved verbatim from the
# relocation, so the runtime contract is identical to reprobuild's shim.
#
# The shim builds on nim-stackable-hooks. In the repo-managed workspace the
# sibling lives at ../nim-stackable-hooks/src (override with
# $STACKABLE_HOOKS_SRC). io-mon's own sources are on --path:src.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

# Both the output library dir and the nimcache dir are overridable with
# ABSOLUTE paths so a consumer can build this shim while io-mon's own source
# tree is READ-ONLY (e.g. when io-mon is a Nix flake input / store path, as in
# reprobuild's package build and dev shell). Defaulting nimcache to the
# relative `build/nimcache` would `mkdir`/write inside the read-only source and
# fail with "Permission denied" / "Read-only file system".
out_dir="${IO_MON_SHIM_OUT_DIR:-build/lib}"
nimcache_dir="${IO_MON_SHIM_NIMCACHE_DIR:-build/nimcache}"
mkdir -p "$out_dir" "$nimcache_dir"

stackable_hooks_src="${STACKABLE_HOOKS_SRC:-../nim-stackable-hooks/src}"
if [ ! -d "$stackable_hooks_src" ]; then
  echo "missing nim-stackable-hooks at $stackable_hooks_src; set STACKABLE_HOOKS_SRC" >&2
  exit 2
fi

nim_mode_flags=()
case "${IO_MON_BUILD_MODE:-debug}" in
  debug) ;;
  release) nim_mode_flags+=("-d:release") ;;
  *)
    echo "unsupported IO_MON_BUILD_MODE=${IO_MON_BUILD_MODE}; expected debug or release" >&2
    exit 2
    ;;
esac

case "$(uname -s)" in
  Darwin)
    macos_shim_arch_flags=()
    if [ "$(uname -m)" = "arm64" ]; then
      macos_shim_arch_flags+=(
        "--passC:-arch arm64"
        "--passC:-arch arm64e"
        "--passL:-arch arm64"
        "--passL:-arch arm64e"
      )
    fi
    nim c \
      ${nim_mode_flags[@]+"${nim_mode_flags[@]}"} \
      ${macos_shim_arch_flags[@]+"${macos_shim_arch_flags[@]}"} \
      --app:lib \
      --threads:on \
      --path:src \
      --path:"${stackable_hooks_src}" \
      --nimcache:"${nimcache_dir}/io-mon-shim-dylib" \
      --out:"${out_dir}/librepro_monitor_shim.dylib" \
      src/io_mon/shim/macos_interpose.nim
    ;;
  Linux)
    nim c \
      ${nim_mode_flags[@]+"${nim_mode_flags[@]}"} \
      --app:lib \
      --threads:on \
      --path:src \
      --path:"${stackable_hooks_src}" \
      --nimcache:"${nimcache_dir}/io-mon-shim-so" \
      --out:"${out_dir}/librepro_monitor_shim.so" \
      src/io_mon/shim/linux_preload.nim
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    nim c \
      ${nim_mode_flags[@]+"${nim_mode_flags[@]}"} \
      --app:lib \
      --threads:on \
      --mm:orc \
      --cc:gcc \
      --path:src \
      --path:"${stackable_hooks_src}" \
      --nimcache:"${nimcache_dir}/io-mon-shim-dll" \
      --out:"${out_dir}/librepro_monitor_shim.dll" \
      src/io_mon/shim/windows_interpose.nim
    ;;
  *)
    echo "unsupported platform $(uname -s) for the io-mon shim" >&2
    exit 2
    ;;
esac

echo "built io-mon shim into ${out_dir}"
