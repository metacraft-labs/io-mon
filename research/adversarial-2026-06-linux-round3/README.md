# Linux adversarial hardening round 3

Date: 2026-06-30
Host OS: Linux
Base io-mon revision: d2c451d5e009cc6ccd74b5eb5388e2b525825651

This corpus preserves the read-only probe campaigns run against the Linux
LD_PRELOAD backend:

- `raw_syscalls/` - raw `syscall(2)` open/read/statx and io_uring probe sources.
- `copy_clone/` - copy/clone/link/rename source-dependency probes.
- `ipc_exec/` - Unix/TCP daemon IPC and exec-boundary probes.
- `identity_kill/` - kill-before-flush, raw syscall, socket daemon, and exec probes.
- `nonfile_path/` - non-file determinism, path fidelity, O_RDWR, mmap, and link probes.

Fixed in this round:

- glibc `fopen`/`fread` on Linux now records the opened stream as a file-open and
  the stream read as a file-read, restoring the ordinary C stdio baseline.
- Linux `connect(2)` now records `mrIpcConnect`; out-of-tree Unix-socket daemon
  reads fail closed as `mcIncomplete` through the existing merge-time IPC
  downgrade.

Carried forward:

- raw syscall and `openat2` reads remain in-process invisible to LD_PRELOAD.
- raw zero-copy syscalls (`sendfile`, `splice`, raw `copy_file_range`) still need
  Linux-specific hooks or a native backend.
- path-fidelity gaps remain for `access`, `readlink`, `statx`, hardlink aliases,
  and rename staging.
- non-file determinism on Linux (`getenv`, `uname`, `sysconf`, time, `getrandom`)
  remains unimplemented.
