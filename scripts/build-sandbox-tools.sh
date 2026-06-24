#!/usr/bin/env bash
# Build a self-contained, relocatable macOS "sandbox-tools" bundle: non-SIP
# drop-in replacements for the SIP-protected system binaries that a monitored
# process tree shells out to (/bin/sh, /bin/cat, /usr/bin/grep, …).
#
# WHY THIS EXISTS (SIP / AMFI rationale — see
# reprobuild-specs/Portable-Macos-Sandbox-Tools.milestones.org and
# codetracer-specs §16.7.8):
#   On macOS 26 / Apple Silicon, System Integrity Protection strips
#   DYLD_INSERT_LIBRARIES when a binary under /bin, /sbin, /usr/bin, /usr/sbin
#   is exec'd, and AMFI SIGKILLs a *copy* of a restricted platform binary on
#   launch even when ad-hoc re-signed. So the io-mon monitor's SIP bypass
#   (rewriteExecPathForSip → rewriteSipPath) must redirect a SIP exec to a
#   binary WE provide that is NOT itself SIP/hardened — a non-Apple GNU build.
#   The injected shim then loads into the drop-in and follows the process tree
#   across the SIP boundary instead of going blind.
#
# WHAT THIS PRODUCES:
#   A directory (default: build/sandbox-tools) shaped like the SIP filesystem,
#   so rewriteSipPath("/bin/cat", DIR) == "DIR/bin/cat" resolves:
#       DIR/bin/<tool>        (mirrors /bin)
#       DIR/usr/bin/<tool>    (mirrors /usr/bin)
#       DIR/bin/sh -> bash    (so a /bin/sh redirect lands on a real shell)
#       DIR/lib/<dylib>       (bundled non-system dylibs, if any)
#   Every Mach-O is relocated with install_name_tool so it carries NO
#   /nix/store references and runs on a machine without Nix — this is the
#   distribution-grade drop-in source CT_SANDBOX_TOOLS_DIR can point at, vs the
#   dev-shell PATH symlinks that io-mon's populateReproSandboxTools drops in.
#
# This replicates agent-harbor's nix/packages.nix `sandbox-tools-portable`
# recipe (symlinkJoin of bash/coreutils/findutils/grep/awk/sed/tar/gzip + copy
# real binaries out of /nix/store + bundle dylibs + install_name_tool -change
# … @executable_path/../lib/…), but as a standalone script so io-mon does not
# need a nix flake. The from-source reprobuild build of these same tools is the
# tracked follow-up (Portable-Macos-Sandbox-Tools.milestones.org M1–M3).
#
# SOURCE OF TOOLS: by default the non-SIP tools currently on PATH (the nix dev
# shell's coreutils/bash/…). Override the lookup with $SANDBOX_TOOLS_PATH.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build-sandbox-tools.sh is macOS-only (no-op on $(uname -s))" >&2
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${SANDBOX_TOOLS_OUT_DIR:-$here/build/sandbox-tools}"
lookup_path="${SANDBOX_TOOLS_PATH:-$PATH}"

# install_name_tool / otool: prefer the cctools the dev shell provides; fall
# back to the SIP /usr/bin copies (fine — we only READ + relocate with them).
otool_bin="$(command -v otool || echo /usr/bin/otool)"
install_name_tool_bin="$(command -v install_name_tool || echo /usr/bin/install_name_tool)"

# The tool set mirrors agent-harbor's sandbox-tools paths list plus the
# coreutils/POSIX commands io-mon's reproSandboxBinaries drops in. We resolve
# each by basename against $lookup_path, skipping anything that is SIP-protected
# or missing. Keep this list in sync with reproSandboxBinaries in
# src/io_mon/fs_snoop.nim (same realistic tool set, different delivery).
TOOLS=(
  # shells (bash provides sh)
  bash dash zsh
  # coreutils
  cat ls cp mv rm mkdir rmdir ln pwd echo date sleep chmod df
  head tail wc sort uniq cut tr basename dirname touch true false test
  printf tee expr seq comm join paste od cksum
  env nproc stat
  # findutils / grep / sed / awk
  find xargs grep egrep fgrep sed awk gawk
  # archivers / compressors
  tar gzip gunzip xz
  # misc
  which diff cmp
)

is_sip_path() {
  case "$1" in
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*) return 0 ;;
    *) return 1 ;;
  esac
}

# Resolve a tool basename to a NON-SIP absolute path on $lookup_path, following
# symlinks to the real Mach-O so we copy a relocatable file (a nix `sh` symlink
# points at bash; we want the bash binary).
resolve_non_sip() {
  local name="$1" dir cand
  local IFS=:
  for dir in $lookup_path; do
    [ -n "$dir" ] || continue
    cand="$dir/$name"
    [ -f "$cand" ] || continue
    if is_sip_path "$cand"; then continue; fi
    # Resolve symlinks to the underlying real binary.
    if command -v readlink >/dev/null 2>&1; then
      local real
      real="$(readlink -f "$cand" 2>/dev/null || true)"
      [ -n "$real" ] && cand="$real"
    fi
    is_sip_path "$cand" && continue
    printf '%s\n' "$cand"
    return 0
  done
  return 1
}

# Copy $1 (a real Mach-O) to $out_dir/bin/$2, bundling its non-system dylibs
# into $out_dir/lib and rewriting references to @executable_path/../lib/…
copy_and_relocate() {
  local src="$1" name="$2"
  local dest="$out_dir/bin/$name"
  cp "$src" "$dest"
  chmod u+w "$dest"

  # Only Mach-O files need dylib relocation (scripts pass straight through).
  if ! file "$dest" 2>/dev/null | grep -q "Mach-O"; then
    return 0
  fi

  # Bundle + rewrite each non-system dylib dependency.
  local dylib dylib_name
  while IFS= read -r dylib; do
    [ -n "$dylib" ] || continue
    case "$dylib" in
      /usr/lib/*|/System/*|@rpath/*|@executable_path/*|@loader_path/*) continue ;;
    esac
    dylib_name="$(basename "$dylib")"
    if [ ! -f "$out_dir/lib/$dylib_name" ] && [ -f "$dylib" ]; then
      cp "$dylib" "$out_dir/lib/$dylib_name"
      chmod u+w "$out_dir/lib/$dylib_name"
      # Recurse one level into the dylib's own non-system deps.
      local sub sub_name
      while IFS= read -r sub; do
        [ -n "$sub" ] || continue
        case "$sub" in
          /usr/lib/*|/System/*|@rpath/*|@executable_path/*|@loader_path/*) continue ;;
        esac
        sub_name="$(basename "$sub")"
        if [ ! -f "$out_dir/lib/$sub_name" ] && [ -f "$sub" ]; then
          cp "$sub" "$out_dir/lib/$sub_name"
          chmod u+w "$out_dir/lib/$sub_name"
        fi
        "$install_name_tool_bin" -change "$sub" \
          "@loader_path/../lib/$sub_name" "$out_dir/lib/$dylib_name" 2>/dev/null || true
      done < <("$otool_bin" -L "$out_dir/lib/$dylib_name" 2>/dev/null | tail -n +2 | awk '{print $1}')
    fi
    "$install_name_tool_bin" -change "$dylib" \
      "@executable_path/../lib/$dylib_name" "$dest" 2>/dev/null || true
  done < <("$otool_bin" -L "$dest" 2>/dev/null | tail -n +2 | awk '{print $1}')
}

rm -rf "$out_dir"
mkdir -p "$out_dir/bin" "$out_dir/usr/bin" "$out_dir/lib"

declare -a missing=()
declare -a copied=()
for name in "${TOOLS[@]}"; do
  if src="$(resolve_non_sip "$name")"; then
    copy_and_relocate "$src" "$name"
    copied+=("$name")
  else
    missing+=("$name")
  fi
done

# bash provides the POSIX shell: expose it as `sh` so a /bin/sh SIP redirect
# lands on a real shell. Mirror as both bin/sh and usr/bin/sh.
if [ -f "$out_dir/bin/bash" ]; then
  ln -sf bash "$out_dir/bin/sh"
fi

# Mirror every produced tool into usr/bin so a /usr/bin/<tool> SIP redirect
# resolves too (macOS ships many tools at BOTH /bin and /usr/bin; a test may
# invoke either path). Relative symlinks keep the bundle relocatable.
for f in "$out_dir/bin"/*; do
  [ -e "$f" ] || continue
  ln -sf "../../bin/$(basename "$f")" "$out_dir/usr/bin/$(basename "$f")"
done

# Relocate each bundled dylib's own install-name off /nix/store.
for lib in "$out_dir/lib"/*; do
  [ -e "$lib" ] || continue
  if file "$lib" 2>/dev/null | grep -q "Mach-O"; then
    "$install_name_tool_bin" -id "@loader_path/$(basename "$lib")" "$lib" 2>/dev/null || true
  fi
done

# Verify no /nix/store references remain in any bundled Mach-O.
portability_ok=1
for f in "$out_dir/bin"/* "$out_dir/lib"/*; do
  [ -f "$f" ] || continue
  if file "$f" 2>/dev/null | grep -q "Mach-O"; then
    if "$otool_bin" -L "$f" 2>/dev/null | tail -n +2 | grep -q "/nix/store"; then
      echo "WARNING: $f still references /nix/store:" >&2
      "$otool_bin" -L "$f" | tail -n +2 | grep "/nix/store" >&2
      portability_ok=0
    fi
  fi
done

echo "sandbox-tools bundle: $out_dir"
echo "  copied: ${#copied[@]} tools (${copied[*]})"
if [ "${#missing[@]}" -gt 0 ]; then
  echo "  skipped (no non-SIP source on PATH): ${missing[*]}" >&2
fi
if [ "$portability_ok" -eq 1 ]; then
  echo "  portability: OK (no /nix/store references)"
else
  echo "  portability: INCOMPLETE (see warnings above)" >&2
fi
