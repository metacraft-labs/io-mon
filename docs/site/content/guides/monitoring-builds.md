---
title: Monitoring Builds
description: Learn how to wrap compilers, build tools, shell scripts, capture stdio, and manage SIP and daemons.
section: guides
order: 1
---

# Monitoring Builds

This guide covers practical considerations when using `io-mon` to wrap real-world build tools, compilers, and test suites.

---

## Command Wrapping & Exit Codes

The syntax for monitoring any command line is:

```bash
io-mon run [options] -- <command> [args...]
```

### Exit Code Behaviour

`io-mon` transparently propagates the monitored command's exit status:

- If the monitored command exits with code `0`, `io-mon` exits with `0`.
- If the command fails with exit code `42`, `io-mon` exits with `42`.
- If `io-mon` itself encounters a setup or monitor-level failure (e.g. missing shim library or invalid arguments), it prints an error to `stderr` and exits with a non-zero monitor error code.

This guarantees that build scripts relying on `set -e` or standard exit status checks can safely prefix any step with `io-mon run`.

---

## Child Process Trees

Most modern compilers are not monolithic executables:

- `gcc` or `clang` invoke sub-processes such as preprocessors, compiler passes (`cc1`), assemblers (`as`), and linkers (`ld`).
- Language runners like `rustc`, `go build`, or `npm` spawn multi-threaded or multi-process pipelines.

`io-mon` automatically hooks child creation across `fork`, `execve`, and `posix_spawn`. You do not need to wrap sub-commands individually; wrapping the top-level command captures the entire tree.

---

## Capturing Standard I/O

By default, the monitored child inherits the parent's `stdin`, `stdout`, and `stderr`.

When running inside an automated build engine (like `reprobuild`), you may want `io-mon` to capture standard output and standard error:

```bash
# Capture merged stdout and stderr in-memory
io-mon run --capture-stdio --depfile build.iomon -- make

# Capture and write merged output to a dedicated file
io-mon run --capture-stdio-path build.log --depfile build.iomon -- make
```

---

## macOS & System Integrity Protection (SIP)

On macOS, binaries protected by System Integrity Protection (such as `/bin/sh`, `/bin/cat`, `/usr/bin/tar`) strip `DYLD_INSERT_LIBRARIES` upon execution. If a build script invokes `/bin/sh`, child monitoring would normally break.

To ensure uninterrupted observation:

- `io-mon` automatically creates clean, non-SIP wrapper drop-ins for standard utilities during execution.
- You can optionally point `CT_SANDBOX_TOOLS_DIR` at a pre-built directory of portable coreutils:

```bash
export CT_SANDBOX_TOOLS_DIR=/opt/metacraft/sandbox-tools
io-mon run --depfile build.iomon -- ./build.sh
```

---

## Compiler Daemons & Breakaway Processes

Some build environments use long-running daemon processes (such as Gradle daemon or local compilation caches). If a child connects via IPC to an unmonitored external process, `io-mon` detects the socket connection (`mrIpcConnect`) and conservatively flags the run as `mcIncomplete` to avoid missing out-of-band dependencies.

If the daemon is trusted and cooperates with `io-mon`:

- Configure the daemon to emit breakaway dependency reports into a shared directory.
- Point `IO_MON_BREAKAWAY_REPORT_DIR` at that location.
- `io-mon` will merge the daemon's recorded reads into the main depfile and exempt the connection from downgrading completeness.
