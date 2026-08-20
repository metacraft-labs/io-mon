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

# The shim's dep queue (io_mon/shm/dep_queue) imports the extracted
# `shm_queue/ring` MPSC ring (metacraft-labs/nim-shm-queue). Layer 1 is pure
# std/posix — NO serialization dependency — so the shim stays serialization-free.
# Sibling at ../nim-shm-queue/src in the workspace; override with $SHM_QUEUE_SRC
# when building from a read-only store path (Nix flake input), same discipline
# as STACKABLE_HOOKS_SRC.
shm_queue_src="${SHM_QUEUE_SRC:-../nim-shm-queue/src}"
if [ ! -d "$shm_queue_src" ]; then
  echo "missing nim-shm-queue at $shm_queue_src; set SHM_QUEUE_SRC" >&2
  exit 2
fi

# io-mon-Lossless-Event-Capture M3 (part 1) — the shim's dependency producer now
# publishes into the nim-shm-gset SET transport (io_mon/writer attaches it when
# REPRO_MONITOR_DEP_SHM names a `.shard0` path). Pure std/posix on the insert hot
# path — serialization-free, fork/orc-safe. Sibling at ../nim-shm-gset/src;
# override with $SHM_GSET_SRC when building from a read-only store path.
shm_gset_src="${SHM_GSET_SRC:-../nim-shm-gset/src}"
if [ ! -d "$shm_gset_src" ]; then
  echo "missing nim-shm-gset at $shm_gset_src; set SHM_GSET_SRC" >&2
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

# Platform/arch detection must not depend on an external ``uname``.
#
# This script is invoked by reprobuild's scripts/build_apps.sh, which runs both
# directly and as a MONITORED build action under ``repro build``. In the
# monitored case on macOS the engine injects this very shim into every child
# process, and ``$(uname -s)`` has been observed to expand to the EMPTY string
# there: reprobuild's v0.1.3 release failed with
#
#   unsupported platform  for the io-mon shim
#
# -- note the doubled space where the platform name belongs -- roughly three
# minutes after this same script had completed successfully outside the engine
# in the same job. Depending on a forked binary to learn what OS we are on is
# the fragile part; ``$OSTYPE`` and ``$HOSTTYPE`` are bash builtins that need
# no fork, no PATH lookup, and offer nothing for a monitoring shim to
# interpose.
#
# ``uname`` remains the fallback, and an unresolvable platform is a hard error
# rather than a guess -- the ``*)`` arm below is a real "unsupported OS", so
# silently landing there because a subprocess returned nothing would report the
# wrong cause (which is exactly what happened).
io_mon_host_platform() {
  case "${OSTYPE:-}" in
    darwin*) printf 'darwin\n'; return 0 ;;
    linux*) printf 'linux\n'; return 0 ;;
    msys*|cygwin*|win32) printf 'windows\n'; return 0 ;;
  esac
  case "$(uname -s 2>/dev/null || true)" in
    Darwin) printf 'darwin\n'; return 0 ;;
    Linux) printf 'linux\n'; return 0 ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT) printf 'windows\n'; return 0 ;;
  esac
  return 1
}

io_mon_host_is_arm64() {
  case "${HOSTTYPE:-}${MACHTYPE:-}" in
    *arm64*|*aarch64*) return 0 ;;
  esac
  case "$(uname -m 2>/dev/null || true)" in
    arm64|aarch64) return 0 ;;
  esac
  return 1
}

if ! io_mon_host_platform_name="$(io_mon_host_platform)"; then
  echo "error: cannot determine the host platform for the io-mon shim." >&2
  echo "       \$OSTYPE='${OSTYPE:-}'; 'uname -s' gave '$(uname -s 2>/dev/null || true)'." >&2
  echo "       This is a detection failure, NOT an unsupported OS -- refusing to" >&2
  echo "       report the wrong cause. If this fired under 'repro build', the" >&2
  echo "       action environment is not resolving subprocesses." >&2
  exit 2
fi

case "${io_mon_host_platform_name}" in
  darwin)
    macos_shim_arch_flags=()
    if io_mon_host_is_arm64; then
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
      --path:"${shm_queue_src}" \
      --path:"${shm_gset_src}" \
      --nimcache:"${nimcache_dir}/io-mon-shim-dylib" \
      --out:"${out_dir}/librepro_monitor_shim.dylib" \
      src/io_mon/shim/macos_interpose.nim
    ;;
  linux)
    linux_shim_link_flags=()
    if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
      linux_shim_link_flags+=(
        "--passL:-Wl,--version-script=${here}/src/io_mon/hooks/linux_preload_versions.map"
      )
    fi
    nim c \
      ${nim_mode_flags[@]+"${nim_mode_flags[@]}"} \
      ${linux_shim_link_flags[@]+"${linux_shim_link_flags[@]}"} \
      --app:lib \
      --threads:on \
      --path:src \
      --path:"${stackable_hooks_src}" \
      --path:"${shm_queue_src}" \
      --path:"${shm_gset_src}" \
      --nimcache:"${nimcache_dir}/io-mon-shim-so" \
      --out:"${out_dir}/librepro_monitor_shim.so" \
      src/io_mon/shim/linux_preload.nim
    ;;
  windows)
    # -static-libgcc: the shim is LoadLibraryW'd into arbitrary children by the
    # engine, so it must resolve with no help from the child's DLL search path.
    # Linked dynamically it imports libgcc_s_seh-1.dll, which lives in whichever
    # mingw bin dir built it and is NOT on the PATH the engine composes for a
    # monitored action -- the child then fails with
    #   repro internal io monitor: error: LoadLibraryW in child returned NULL
    # and every monitored action on Windows fails. Static-linking the gcc
    # runtime leaves only KERNEL32 + the api-ms-win-crt-* UCRT stubs, all of
    # which the system resolves unconditionally.
    nim c \
      ${nim_mode_flags[@]+"${nim_mode_flags[@]}"} \
      --app:lib \
      --threads:on \
      --mm:orc \
      --cc:gcc \
      --passL:"-static-libgcc" \
      --path:src \
      --path:"${stackable_hooks_src}" \
      --path:"${shm_queue_src}" \
      --path:"${shm_gset_src}" \
      --nimcache:"${nimcache_dir}/io-mon-shim-dll" \
      --out:"${out_dir}/librepro_monitor_shim.dll" \
      src/io_mon/shim/windows_interpose.nim

    # 32-bit (WOW64) companions.
    #
    # A 64-bit shim cannot be injected into a 32-bit child: LoadLibraryW
    # returns NULL on the machine-type mismatch, the child is left
    # unmonitored, and the action is graded an unmonitored-subtree loss --
    # which costs the whole build its cache publication. 32-bit children are
    # not exotic on Windows: PATH trampolines (scoop shims) and older
    # toolchain binaries (the ezwinports make.exe) are routinely i386.
    #
    # Two artefacts, both found by convention rather than configuration --
    # see the WOW64 section of nim-stackable-hooks'
    # src/stackable_hooks/windows_injector.nim:
    #
    #   librepro_monitor_shim32.dll         the 32-bit shim
    #   stackable_hooks_wow64_probe32.exe   reports the 32-bit kernel32
    #                                       proc addresses the injector
    #                                       cannot resolve for itself,
    #                                       via its exit code
    #
    # Optional: a host with no i686 toolchain still gets a working 64-bit
    # shim, and the injector fails with a specific "32-bit shim is missing,
    # build it with --cpu:i386" message if it ever meets a 32-bit child.
    # Install one with: pacman -S mingw-w64-i686-gcc
    i686_gcc="${IO_MON_I686_GCC:-}"
    if [ -z "${i686_gcc}" ] && command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
      i686_gcc="$(command -v i686-w64-mingw32-gcc)"
    fi
    if [ -n "${i686_gcc}" ]; then
      # The i686 gcc.exe links its own libgcc_s_dw2-1.dll +
      # libwinpthread-1.dll from its bin dir. nim spawns the compiler with
      # the ambient PATH, so without that directory on it the compiler fails
      # to START -- exit 1 with no diagnostic, which reads as a compile error
      # against whichever .c file happened to be first. Scope the addition to
      # the 32-bit invocations only: on the global PATH it makes the 64-bit
      # build pick up the i686 compiler and fail on a pointer-size assert.
      i686_bin="$(dirname "${i686_gcc}")"
      # A bash PATH is colon-separated, so a Windows-style "D:/..." entry
      # would split at the drive colon into "D" and "/...". Convert to the
      # shell's own path form where cygpath is available (MSYS2 / git-bash).
      if command -v cygpath >/dev/null 2>&1; then
        i686_bin="$(cygpath -u "${i686_bin}")"
      fi
      # --kill-at: 32-bit mingw decorates stdcall exports with the callee's
      # argument-byte count, so `repro_runtime_init` (a stdcall entry taking
      # one pointer) is exported as `repro_runtime_init@4`, while the 64-bit
      # build -- where there is no stdcall to decorate -- exports it plain.
      # Every lookup asks for the undecorated name: the shim resolves its own
      # init to compute the RVA it starts in the child, and the spawn hook
      # passes the literal string to injectShimIntoChild. Both would return
      # NULL against a decorated export, and neither failure is visible from
      # outside -- LoadLibraryW succeeds, the DLL sits in the child with no
      # hooks installed, and the process reports no records at all while the
      # run still grades mcComplete. Stripping the decoration keeps ONE export
      # name across both bitnesses, which is what the injector's naming
      # convention already assumes.
      PATH="${i686_bin}:${PATH}" \
      nim c \
        ${nim_mode_flags[@]+"${nim_mode_flags[@]}"} \
        --app:lib \
        --threads:on \
        --mm:orc \
        --cpu:i386 \
        --cc:gcc \
        --gcc.exe:"${i686_gcc}" \
        --gcc.linkerexe:"${i686_gcc}" \
        --passL:"-static-libgcc" \
        --passL:"-Wl,--kill-at" \
        --path:src \
        --path:"${stackable_hooks_src}" \
        --path:"${shm_queue_src}" \
        --path:"${shm_gset_src}" \
        --nimcache:"${nimcache_dir}/io-mon-shim-dll32" \
        --out:"${out_dir}/librepro_monitor_shim32.dll" \
        src/io_mon/shim/windows_interpose.nim

      PATH="${i686_bin}:${PATH}" \
      nim c \
        --app:console \
        --cpu:i386 \
        --cc:gcc \
        --gcc.exe:"${i686_gcc}" \
        --gcc.linkerexe:"${i686_gcc}" \
        --passL:"-static-libgcc" \
        --nimcache:"${nimcache_dir}/wow64-probe32" \
        --out:"${out_dir}/stackable_hooks_wow64_probe32.exe" \
        "${stackable_hooks_src}/stackable_hooks/tools/wow64_proc_probe.nim"

      echo "built 32-bit WOW64 shim + probe into ${out_dir}"
    else
      echo "note: no i686 toolchain found (set IO_MON_I686_GCC or install" \
        "mingw-w64-i686-gcc); 32-bit children will not be injectable" >&2
    fi
    ;;
  *)
    # Reachable only for a platform we genuinely do not support: detection
    # itself already failed hard above, so this can no longer be reached by a
    # subprocess returning nothing.
    echo "unsupported platform ${io_mon_host_platform_name} for the io-mon shim" >&2
    exit 2
    ;;
esac

echo "built io-mon shim into ${out_dir}"
