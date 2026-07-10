## test_io_mon_inline_syscall_boundary — FUP-H regression pin (Linux).
##
## Guards the instruction-boundary awareness of the LIVE syscall-site
## scanner ``visitLinuxX8664SyscallMemory`` that drives inline-syscall
## INT3 patching.
##
## ROOT CAUSE (see nim-stackable-hooks
## ``platform/linux_raw_syscalls.nim`` FUP-H comments): the scanner used to
## match ``0f 05`` at the BYTE level, with only two ad-hoc false-positive
## guards (trailing ``00`` immediate; a preceding ``e8``/``e9`` rel32
## branch). That cannot tell a real ``syscall`` instruction from the SAME
## two bytes appearing MID-INSTRUCTION. The ``codetracer-visual-replay``
## Vulkan-replay test binaries contain exactly such a site:
##
##   4b 0f b6 74 0f 05 44 ...
##   └─ REX.WXB ─ movzx r32, byte ptr [reg + reg*1 + 0x05] ─┘
##
## Here ``0f 05`` is the SIB byte (``0f``) + disp8 (``05``) of a 6-byte
## ``movzx``, NOT a ``syscall``. The old byte scanner reported it as a
## syscall site; INT3-patching the ``0f`` rewrote the ``movzx``'s SIB byte
## and corrupted the containing instruction, which manifested as
## device-memory-readback zeroing and executor/snapshot-teardown
## SIGSEGV/SIGBUS under the monitor (the 8 ``test_vk_*`` visual-replay
## tests). Same class the M9.R.67.1 ``/nix/store`` cc1 exclusion was a
## partial band-aid for — but the main monitored executable is never
## ``/nix/store``-excluded, so a length-aware scan is the real fix.
##
## After the FUP-H fix: the scanner walks forward one DECODED instruction at
## a time (x86-64 length decoder) and only reports a ``0f 05`` that BEGINS a
## complete 2-byte instruction. A ``0f 05`` consumed by a longer instruction
## is never presented as a candidate boundary, so it is never patched.

import std/[unittest]

import stackable_hooks/platform/linux_raw_syscalls

when defined(linux) and defined(amd64):
  proc collectSites(bytes: seq[byte]): seq[int] =
    ## Report the byte offsets the live memory scanner would INT3-patch.
    var offs: seq[int] = @[]
    if bytes.len == 0:
      return offs
    var buf = bytes
    let sink = addr offs
    visitLinuxX8664SyscallMemory(addr buf[0], buf.len,
      proc(site: LinuxSyscallSite): bool {.closure, raises: [].} =
        sink[].add site.offset
        true)
    offs

  suite "FUP-H inline-syscall scanner instruction-boundary awareness":

    test "mid-instruction 0f 05 (movzx SIB+disp8) is NOT reported":
      # nop; movzx r32, byte ptr [.. + 0x05]; syscall; ret
      #  0x90 | 4b 0f b6 74 0f 05 | 0f 05 | c3
      # offsets: nop@0  movzx@1..6  (embedded 0f05 at offset 5)  syscall@7  ret@9
      let bytes = @[
        byte 0x90,
        0x4b, 0x0f, 0xb6, 0x74, 0x0f, 0x05,   # movzx (6 bytes) — 0f05 @ off 5
        0x0f, 0x05,                            # real syscall @ off 7
        0xc3]
      let sites = collectSites(bytes)
      # The real syscall at offset 7 IS reported.
      check 7 in sites
      # The mid-movzx 0f 05 at offset 5 is NOT reported (the pre-fix byte
      # scanner reported it — this is the regression that corrupted the
      # monitored program).
      check 5 notin sites
      check sites == @[7]

    test "a bare aligned syscall is still reported":
      # mov eax, 60 ; syscall  (B8 3C 00 00 00 | 0F 05 | C3)
      let bytes = @[
        byte 0xb8, 0x3c, 0x00, 0x00, 0x00,     # mov eax, 60
        0x0f, 0x05,                            # syscall @ off 5
        0xc3]
      let sites = collectSites(bytes)
      check sites == @[5]

    test "trailing-00 and rel32-displacement guards still hold":
      # jmp rel32 whose displacement begins 0f 05 must not be a site, and a
      # 0f 05 00 (immediate) must not be a site.
      # e9 0f 05 00 00  = jmp rel32 (0x0000050f); then a real syscall.
      let bytes = @[
        byte 0xe9, 0x0f, 0x05, 0x00, 0x00,     # jmp rel32 — 0f05 in disp
        0x0f, 0x05,                            # real syscall @ off 5
        0xc3]
      let sites = collectSites(bytes)
      check 1 notin sites
      check sites == @[5]
