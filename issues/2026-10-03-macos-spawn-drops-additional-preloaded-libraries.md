# macOS spawn drops additional preloaded libraries

Observed on macOS ARM64 at `5c5b82a71304e1581809cbddf2fd5337c23ee4ee`.

The transparency contract in `docs/contributors/architecture.md` requires
monitored launches to preserve program behavior. The comment on
`repro_macos_env_with_preload` also promises to preserve the caller's additional
libraries while ensuring the monitor is present once.

When `DYLD_INSERT_LIBRARIES` already contains the active shim, the helper
replaces the whole list with that shim alone. Additional requested libraries
therefore never load in the child. This also removes a distinct inner shim
when an outer monitor propagates its own library.

## Real reproducer

Compile two dylibs exporting independent marker functions and a C launcher.
Start the launcher with only the monitor, then request both marker libraries in
the child's environment. With the shim already first or last in that list,
`posix_spawn`, `POSIX_SPAWN_SETEXEC` and `execve` all produce a child whose
`dlsym` cannot find either marker. The child exits 11. Both interpose-only and
combined backends reproduce it. The control omitting the shim from the caller's
list loads both libraries successfully.

The regression also requires captured input evidence and exactly one monitor
entry. Local failing log: `/tmp/io-mon-preload-libraries-before.log`.

## Archive search

Fetched current `agents@5c5b82a` and checked current issues and deleted issue
history for DYLD, preload, library propagation and nested sessions. The open
nested-session issue records startup and evidence ownership; it does not record
this independent loss of an application's requested libraries.

## Repair

Retain the existing list when it already contains the monitor. Prepend the
monitor only when absent. Do not change library order, silently drop other
libraries or append another copy of the monitor.
