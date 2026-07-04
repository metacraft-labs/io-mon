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
