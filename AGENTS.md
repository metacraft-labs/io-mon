# AGENTS.md — io-mon Developer Assistant Index

This repository provides cross-platform filesystem and process activity monitoring for Nim.

## Quick Reference Commands

- **Build all**: `just build` (compiles shim shared library and CLI)
- **Run test suite**: `just test` (runs portable + host-OS tests)
- **Format code**: `just format`
- **Lint check**: `just lint`

## Codebase Map & Documentation Index

Refer to the documents below to understand how the codebase works, how tests are structured, and what policies to follow when writing code:

### User Facing Documentation

- **[README.md](README.md)**: Main user documentation, overview of responsibilities, features, and platform support.
- **[docs/usage.md](docs/usage.md)**: Details the command-line usage (`io-mon run`, `io-mon inspect`) and public library API (`import io_mon`).

### Contributor & Architecture Documentation

- **[docs/contributors/architecture.md](docs/contributors/architecture.md)**: Core design, the fail-incomplete correctness contract, macOS interpose vs bodypatching, and Linux preload + raw-syscall hooks.
- **[docs/contributors/building-and-testing.md](docs/contributors/building-and-testing.md)**: Shim library and CLI build instructions, test directories (`tests/portable`, `tests/posix`, `tests/macos`, etc.), and test organization guidelines.
- **[docs/contributors/shim-build-policy.md](docs/contributors/shim-build-policy.md)**: Safety guidelines for hooking functions invoked inside libmalloc/dyld, threadvar usage restrictions, and compiler flags/allocator settings.
- Read @docs/contributors/event-transport-and-loss-freedom.md — how observed events travel from a monitored process to the consumer and why that channel must lose nothing: the loss-freedom invariants (LF-1/LF-2), the set-accumulation model, the transport decision (shm ring + backpressure vs OS-primitive MPSC queue vs the new `nim-shm-gset` sharded append-only set), the no-fallback-file requirement, the consumer-liveness contract, the cross-restart reaper, and the per-OS producer arms.
