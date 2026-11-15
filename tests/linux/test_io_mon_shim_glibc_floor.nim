## test_io_mon_shim_glibc_floor — the shim must not need a newer glibc than
## the hosts it is preloaded into provide (Linux).
##
## THE DEFECT. glibc 2.42 added a `_FORTIFY_SOURCE` wrapper for `inet_ntop`
## (<bits/inet-fortified.h>) that redirects calls to `__inet_ntop_chk`, a
## symbol versioned `GLIBC_2.42` and nothing older. The Nix compiler wrapper
## fortifies by default, so a clang-built shim that called `inet_ntop` came out
## needing `GLIBC_2.42`. The shim is preloaded into every process a monitored
## action runs, host binaries included, and the dynamic loader refuses a
## preload whose version needs the process's libc cannot meet. On a GitHub
## Ubuntu 24.04 runner (glibc 2.39) every host `/bin/sh` then died before
## running a command:
##   /bin/sh: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.42' not found
##   (required by .../librepro_monitor_shim.so)
## and `test_io_mon_dep_identity_scope` saw the sh-launched reads vanish
## (io-mon CI run 43122211701, job "Test (nix, linux-x64)"). Nothing in the
## build failed: a version need is only checked when the library is loaded,
## and the dev shell's own glibc always satisfies it.
##
## WHAT THIS TEST GRADES. The `GLIBC_*` version needs the shim records in
## its `.gnu.version_r` section, on a debug and a `-d:release` shim built
## from source with the suite's own toolchain (the one whose fortify headers
## raised the need), stay at or below `ShimGlibcNeedCeiling`. That ceiling is
## the shim's need as measured at the commit that added this test (`2.34`;
## `GLIBC_2.34` is the libpthread-into-libc merge, `GLIBC_2.33` the
## `stat`-family exports), with a margin of none: any raise is a decision
## about which hosts can be monitored, and has to be made by editing this
## constant on purpose, not discovered on a runner. A newer *build* glibc
## must not leak into the need; that is the property, not a particular
## libc's age.
##
## The version needs are read from the ELF section headers here, so the test
## depends on neither `readelf` nor `objdump`. Layout per the System V gABI
## ("Sections") and the LSB's symbol versioning sections:
##   https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html
##   https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html
##
## Mocks: none. The real shim is built by the real `scripts/build_shim.sh`.

import std/[os, sequtils, strutils, unittest]

import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  ShimGlibcNeedCeiling = @[2, 34]
    ## See the module comment: raise only as a deliberate host-support
    ## decision.

proc readLe(data: string; off, width: int): uint64 =
  doAssert off >= 0 and off + width <= data.len, "read past end of ELF file"
  for i in countdown(width - 1, 0):
    result = (result shl 8) or uint64(ord(data[off + i]))

proc cString(data: string; off: int): string =
  doAssert off >= 0 and off < data.len, "string offset past end of ELF file"
  var i = off
  while i < data.len and data[i] != '\0':
    result.add data[i]
    inc i

proc versionNeeds(path: string): seq[tuple[file, version: string]] =
  ## Every (needed library, version name) pair of the ELF's
  ## `SHT_GNU_verneed` section. Little-endian ELF32 and ELF64 are handled
  ## (every Linux target io-mon builds for); anything else fails the check
  ## rather than guessing.
  const ShtGnuVerneed = 0x6ffffffe'u64
  let data = readFile(path)
  doAssert data.len >= 0x34 and data.startsWith("\x7fELF"),
    path & " is not an ELF file"
  doAssert data[5] == '\x01', path & " is not little-endian"
  let is64 = data[4] == '\x02'
  let shoff = int(if is64: readLe(data, 0x28, 8) else: readLe(data, 0x20, 4))
  let shentsize = int(readLe(data, if is64: 0x3A else: 0x2E, 2))
  let shnum = int(readLe(data, if is64: 0x3C else: 0x30, 2))
  proc section(i: int): tuple[kind: uint64; offset, size, link: int] =
    let sh = shoff + i * shentsize
    doAssert sh + shentsize <= data.len, path & ": truncated section headers"
    if is64:
      (readLe(data, sh + 4, 4), int(readLe(data, sh + 0x18, 8)),
       int(readLe(data, sh + 0x20, 8)), int(readLe(data, sh + 0x28, 4)))
    else:
      (readLe(data, sh + 4, 4), int(readLe(data, sh + 0x10, 4)),
       int(readLe(data, sh + 0x14, 4)), int(readLe(data, sh + 0x18, 4)))
  for i in 0 ..< shnum:
    let verneed = section(i)
    if verneed.kind != ShtGnuVerneed: continue
    let strtab = section(verneed.link).offset
    # Elf_Verneed: vn_version u16, vn_cnt u16, vn_file u32, vn_aux u32,
    # vn_next u32. Elf_Vernaux: vna_hash u32, vna_flags u16, vna_other u16,
    # vna_name u32, vna_next u32. Offsets are relative to the entry.
    var need = verneed.offset
    while true:
      let count = int(readLe(data, need + 2, 2))
      let file = cString(data, strtab + int(readLe(data, need + 4, 4)))
      var aux = need + int(readLe(data, need + 8, 4))
      for _ in 0 ..< count:
        result.add (file, cString(data, strtab + int(readLe(data, aux + 8, 4))))
        let nextAux = int(readLe(data, aux + 12, 4))
        if nextAux == 0: break
        aux += nextAux
      let next = int(readLe(data, need + 12, 4))
      if next == 0: break
      need += next
    return
  doAssert false, path & " has no SHT_GNU_verneed section"

proc glibcVersion(name: string): seq[int] =
  ## `GLIBC_2.3.4` -> @[2, 3, 4]; anything else (`GLIBC_PRIVATE`,
  ## `GLIBC_ABI_DT_RELR`, ...) -> @[].
  if not name.startsWith("GLIBC_"): return
  for part in name["GLIBC_".len .. ^1].split('.'):
    if part.len == 0 or not part.allIt(it in Digits): return @[]
    result.add parseInt(part)

proc newerThan(a, b: seq[int]): bool =
  for i in 0 ..< max(a.len, b.len):
    let x = if i < a.len: a[i] else: 0
    let y = if i < b.len: b[i] else: 0
    if x != y: return x > y
  false

template checkFloor(built: string) =
  # A template, not a proc: unittest's `check` marks the enclosing `test`
  # failed only when it expands inside it (in a proc it merely sets the exit
  # code and the case still prints [OK]).
  let shim = built
  let needs = versionNeeds(shim)
  checkpoint(shim & " needs: " & $needs)
  # Positive control: the parser found the libc needs every shim has, so an
  # empty result below cannot come from reading the wrong section.
  check needs.anyIt(it.file == "libc.so.6" and
                    it.version.glibcVersion.len > 0)
  let tooNew = needs.filterIt(it.version.glibcVersion.newerThan(
    ShimGlibcNeedCeiling))
  check tooNew.len == 0
  if tooNew.len > 0:
    echo "shim needs a glibc newer than ", ShimGlibcNeedCeiling.join("."),
      ": ", tooNew, ". A fortified libc call is the usual cause (see the ",
      "`inet_ntop` note in src/io_mon/shim/linux_preload.nim)."

suite "the shim's glibc version needs":
  test "t_debug_shim_needs_no_newer_glibc":
    checkFloor(buildPrivateLinuxShim(repoRoot))

  test "t_release_shim_needs_no_newer_glibc":
    checkFloor(buildPrivateLinuxShimWithFlags(repoRoot, ["-d:release"]))

  test "t_version_parser_orders_glibc_names":
    check glibcVersion("GLIBC_2.42") == @[2, 42]
    check glibcVersion("GLIBC_2.3.4") == @[2, 3, 4]
    check glibcVersion("GLIBC_PRIVATE").len == 0
    check glibcVersion("GLIBC_ABI_DT_RELR").len == 0
    check @[2, 42].newerThan(ShimGlibcNeedCeiling)
    check @[2, 35].newerThan(ShimGlibcNeedCeiling)
    check not @[2, 34].newerThan(ShimGlibcNeedCeiling)
    check not @[2, 3, 4].newerThan(ShimGlibcNeedCeiling)
