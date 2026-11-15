## Linux: the shim's optimisation level and fortify setting are stated by
## `scripts/build_shim.sh`, not inherited from the compiler wrapper.
##
## nixpkgs' cc-wrapper turns its `fortify` / `fortify3` hardening flags into
## `-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=<n>`, placed BEFORE the caller's
## arguments (`hardeningCFlagsBefore` in
## https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/cc-wrapper/add-hardening.sh).
## Which flags it applies comes from `NIX_HARDENING_ENABLE`, and it reads that
## variable only for the roles a stdenv shell has activated
## (`NIX_CC_WRAPPER_TARGET_HOST_<salt>`). So the same recipe, run by the same
## `repro build` with the same Nix-provisioned gcc, produced a shim compiled
## at -O2 with fortify from a `nix develop` shell and at -O0 without it from
## a plain shell.
## The -O0 build exposed a real defect the -O2 one hid, which is why the
## debug lane stays -O0 and why its level must not depend on the shell.
##
## The case builds the production shim twice per build mode with identical
## environments except for the wrapper's fortify hardening, then checks that
## neither image imports a fortified libc entry (`__*_chk`) and that their
## `.text` sections are byte-identical. Before the fix the hardened debug
## build was -O2 and fortified while its twin was -O0, so both checks fail.
## Equal twins alone would not pin the level itself (two -O2 builds are
## equal too), so the case also reads every C compile command Nim issued
## (`--listCmd`) and requires the last `-O` on each to be the mode's stated
## level, -O0 for debug and -O3 for release. The last one is the one the
## compiler obeys, and the wrapper places its own `-O2` before the caller's
## arguments.
##
## NO MOCKS: the real builder, the real Nix cc-wrapper on `PATH` and the real
## compiler. The fabricated inputs are the two wrapper role variables a stdenv
## shell exports (set explicitly so the case does not depend on the shell it
## was started from) and the two `NIX_HARDENING_ENABLE` values being
## compared, which are the dev shell's own set with and without fortify.

import foreign_preload_isolation

import std/[os, osproc, re, strtabs, strutils, tempfiles, unittest]

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

const
  devShellHardening =
    "bindnow format fortify fortify3 pic relro stackclashprotection " &
    "stackprotector strictflexarrays1 strictoverflow zerocallusedregs"
    ## The hardening set of io-mon's `nix develop` shell (nixpkgs' stdenv
    ## default), the environment in which the shim used to come out at -O2.
  unfortifiedHardening =
    "bindnow format pic relro stackclashprotection " &
    "stackprotector strictflexarrays1 strictoverflow zerocallusedregs"
    ## The same set without the two flags that add `-O2` and
    ## `_FORTIFY_SOURCE`, so the twins differ only in what this case is about.

type ElfSection = tuple[found: bool; offset, size: int]

proc readU16(data: string; at: int): int =
  int(uint8(data[at])) or (int(uint8(data[at + 1])) shl 8)

proc readU32(data: string; at: int): int =
  var v = 0
  for i in countdown(3, 0): v = (v shl 8) or int(uint8(data[at + i]))
  v

proc readU64(data: string; at: int): int =
  var v = 0
  for i in countdown(7, 0): v = (v shl 8) or int(uint8(data[at + i]))
  v

proc elfSection(data, name: string): ElfSection =
  ## Locate a section of a little-endian ELF64 image by name (the System V
  ## gABI section header table,
  ## https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html).
  ## Parsed here rather than read through binutils so the case needs no tool
  ## beyond the compiler it is testing.
  doAssert data.len > 64 and data[0 .. 3] == "\x7fELF", "not an ELF image"
  doAssert data[4] == '\x02' and data[5] == '\x01', "not little-endian ELF64"
  let shoff = readU64(data, 0x28)
  let shentsize = readU16(data, 0x3A)
  let shnum = readU16(data, 0x3C)
  let shstrndx = readU16(data, 0x3E)
  let strtab = shoff + shstrndx * shentsize
  let namesAt = readU64(data, strtab + 0x18)
  for i in 0 ..< shnum:
    let hdr = shoff + i * shentsize
    let nameAt = namesAt + readU32(data, hdr)
    let nameEnd = data.find('\0', nameAt)
    if data[nameAt ..< nameEnd] == name:
      return (true, readU64(data, hdr + 0x18), readU64(data, hdr + 0x20))
  (false, 0, 0)

proc sectionBytes(data, name: string): string =
  let section = elfSection(data, name)
  doAssert section.found, "no " & name & " section"
  data[section.offset ..< section.offset + section.size]

proc fortifiedImports(data: string): seq[string] =
  ## Every UNDEFINED `__<name>_chk` dynamic symbol: a libc entry point
  ## `_FORTIFY_SOURCE` redirected one of the shim's own calls to. Defined
  ## ones are excluded because the shim exports interposers for several of
  ## them (`__read_chk`, `__realpath_chk`, ...) whatever it is compiled with.
  ## ELF64 `Elf64_Sym` is 24 bytes: `st_name` at 0, `st_shndx` at 6, and
  ## `st_shndx == SHN_UNDEF (0)` marks an import.
  let names = sectionBytes(data, ".dynstr")
  let symbols = sectionBytes(data, ".dynsym")
  var at = 0
  while at + 24 <= symbols.len:
    let nameAt = readU32(symbols, at)
    let undefined = readU16(symbols, at + 6) == 0
    if undefined and nameAt > 0:
      let name = names[nameAt ..< names.find('\0', nameAt)]
      if name.startsWith("__") and name.endsWith("_chk"):
        result.add name
    at += 24

proc ccWrapperSalt(gcc: string): string =
  ## The target suffix nixpkgs' cc-wrapper appends to every variable it reads
  ## (`@suffixSalt@`, e.g. `x86_64_unknown_linux_gnu`), taken from the
  ## wrapper script itself. Empty when `gcc` is not a Nix cc-wrapper.
  var matches: array[1, string]
  if readFile(gcc).find(re"NIX_CC_WRAPPER_FLAGS_SET_([A-Za-z0-9_]+)",
                        matches) >= 0:
    result = matches[0]

type ShimBuild = tuple[image, output: string]

proc buildShim(work, mode, hardening, salt: string): ShimBuild =
  ## Build the production shim with `scripts/build_shim.sh` into `work`,
  ## under the stdenv wrapper roles and the given hardening set. Returns the
  ## image path and the builder's output, which carries Nim's `--listCmd`
  ## listing of every C compile (`CC: <module>: <command>`).
  var env = newStringTable(modeCaseSensitive)
  for key, value in envPairs(): env[key] = value
  env["IO_MON_BUILD_MODE"] = mode
  env["IO_MON_SHIM_OUT_DIR"] = work / "lib"
  env["IO_MON_SHIM_NIMCACHE_DIR"] = work / "nimcache"
  env["NIX_CC_WRAPPER_TARGET_HOST_" & salt] = "1"
  env["NIX_BINTOOLS_WRAPPER_TARGET_HOST_" & salt] = "1"
  env["NIX_HARDENING_ENABLE"] = hardening
  let built = execCmdEx("bash " &
    quoteShell(repoRoot / "scripts/build_shim.sh") & " --listCmd", env = env)
  doAssert built.exitCode == 0, "build_shim.sh failed: " & built.output
  result.image = work / "lib" / "librepro_monitor_shim.so"
  result.output = built.output
  doAssert fileExists(result.image), "shim not produced at " & result.image

proc compileLevels(output: string): seq[string] =
  ## The optimisation level each listed C compile ends up with: the last
  ## `-O<level>` word of each `CC:` line, or "none" when a command states
  ## none (the compiler's default, which is not a stated level either).
  for line in output.splitLines():
    if not line.startsWith("CC: "):
      continue
    var level = "none"
    for word in line.splitWhitespace():
      if word.len >= 2 and word.startsWith("-O"):
        level = word
    result.add level

suite "io-mon Linux shim optimisation level":
  let gcc = findExe("gcc")
  doAssert gcc.len > 0, "gcc is not on PATH"
  let salt = ccWrapperSalt(gcc)
  # io-mon's Linux builds always use a Nix cc-wrapper (the flake dev shell
  # and `repro`'s Nix tool provisioning both supply one), and that wrapper
  # is the mechanism under test. Refuse rather than pass vacuously.
  doAssert salt.len > 0, gcc & " is not a nixpkgs cc-wrapper; this case " &
    "tests how the shim build responds to one"

  for mode in ["debug", "release"]:
    test "the " & mode & " shim does not take its level from the wrapper's hardening":
      # Equal-length private trees: build paths reach the image only through
      # strings, but keep their lengths equal so no offset can shift either.
      let hardenedWork = createTempDir("io-mon-shim-opt-a-", "")
      let plainWork = createTempDir("io-mon-shim-opt-b-", "")
      defer:
        removeDir(hardenedWork)
        removeDir(plainWork)
      let hardenedBuild = buildShim(hardenedWork, mode, devShellHardening,
        salt)
      let plainBuild = buildShim(plainWork, mode, unfortifiedHardening, salt)
      let expectedLevel = if mode == "debug": "-O0" else: "-O3"
      for build in [hardenedBuild, plainBuild]:
        let levels = compileLevels(build.output)
        var stray: seq[string]
        for level in levels:
          if level != expectedLevel and level notin stray:
            stray.add level
        checkpoint($levels.len & " C compiles listed; levels other than " &
          expectedLevel & ": " & stray.join(", "))
        # A listing with no compiles would make the level check vacuous.
        check levels.len > 0
        check stray.len == 0
      let hardened = readFile(hardenedBuild.image)
      let plain = readFile(plainBuild.image)
      let hardenedChk = fortifiedImports(hardened)
      let plainChk = fortifiedImports(plain)
      checkpoint("fortified imports with dev-shell hardening: " &
        hardenedChk.join(", "))
      checkpoint("fortified imports without fortify: " & plainChk.join(", "))
      check hardenedChk.len == 0
      check plainChk.len == 0
      let hardenedText = sectionBytes(hardened, ".text")
      let plainText = sectionBytes(plain, ".text")
      # Compare into a flag: `check a == b` would print both images' code.
      var firstDifference = -1
      for i in 0 ..< min(hardenedText.len, plainText.len):
        if hardenedText[i] != plainText[i]:
          firstDifference = i
          break
      let identicalText = hardenedText.len == plainText.len and
        firstDifference < 0
      checkpoint(".text bytes: " & $hardenedText.len & " with dev-shell " &
        "hardening, " & $plainText.len & " without fortify; first " &
        "differing offset " & $firstDifference)
      check identicalText
