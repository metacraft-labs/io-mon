# Inline exit fixture compiles x86 assembly on Linux ARM64

|             |                                                           |
| ----------- | --------------------------------------------------------- |
| Status      | open                                                      |
| Recorded    | 2026-09-29                                                |
| Observed in | io-mon `0f3a186`                                          |
| Area        | `tests/linux/test_io_mon_linux_inline_asm_exit_group.nim` |

## Observed

The real Linux ARM64 diagnostic fails compiling the fixture with
`error: invalid register name for ‘rax’` and `unknown register name ‘rcx’`.
The same fixture passes on x86_64 at the same product revision. The mapping
policy's 10 cases pass both directly and monitored on both architectures.

## Expected

[Building and Testing](../docs/contributors/building-and-testing.md),
“Running the Test Suite”, selects tests by target compatibility.
`linuxRawSyscallSupported()` in the pinned nim-stackable-hooks explicitly
returns `lrsUnsupportedArchitecture` outside Linux x86_64; io-mon's
`installInlineSyscallPatches` honors that contract. This fixture must make
that architecture requirement explicit instead of compiling x86 registers
on ARM64. Keep every x86_64 assertion and report an explicit skip elsewhere.
ARM64 file capture remains covered by the real CLI and Linux stdio fixtures;
this change does not claim an ARM64 inline-syscall patching backend.

## Evidence

[Native ARM64 failure](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36487275617/job/109147123337),
[x86_64 pass](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36487275617/job/109147122916).
Both use product `0f3a186` and diagnostic `a2efcad`.
The downloaded `inline-exit-group.log` contains the compiler diagnostics.

Refreshed dev `279a17b` and searched open and deleted issues with
`git log --all -i -G 'inline.?asm|exit_group|x86.*fixture' -- issues` before
recording; no existing record was found.
