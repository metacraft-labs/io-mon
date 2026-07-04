# Building & Testing io-mon

This guide details how to build and test the `io-mon` monitor, shim libraries, and CLI.

---

## 1. Prerequisites & Sibling Layouts

`io-mon` compiles against `nim-stackable-hooks`. In typical workspace development:

- `nim-stackable-hooks` must be checked out as a sibling directory at `../nim-stackable-hooks/`.
- Paths are resolved automatically by the `Justfile` and `io_mon.nimble` targets.

---

## 2. Compilation Targets

You can build the components using `just` or the `repro` command-line tool.

### Build the Interpose Shim Shared Library

The shim library intercepts system calls in monitored programs. It compiles to `build/lib/librepro_monitor_shim.{dylib,so,dll}`.

```sh
just build-shim
# OR
repro build io-mon:shim
# OR (fallback)
scripts/build_shim.sh
```

### Build the Standalone CLI Snoop tool

The `io-mon` binary runs commands under the shim and writes dependency depfiles. It compiles to `build/bin/io-mon`.

```sh
just build-snoop
# OR
repro build io-mon
# OR (fallback)
nimble buildSnoop
```

---

## 3. Running the Test Suite

Tests are organized into directories based on their target compatibility:

| Directory         | Runs on      | Focus / Scope                                                                                         |
| ----------------- | ------------ | ----------------------------------------------------------------------------------------------------- |
| `tests/portable/` | All OSes     | Pure logic tests (depfile formats, encoders, completeness algorithm checks). Runs without live shims. |
| `tests/posix/`    | POSIX OSes   | Shared POSIX hooks and platform wrapper validations.                                                  |
| `tests/macos/`    | macOS only   | Live macOS interpose + body-patch testing.                                                            |
| `tests/linux/`    | Linux only   | Live Linux `LD_PRELOAD` testing.                                                                      |
| `tests/windows/`  | Windows only | Live Windows hook injection testing.                                                                  |

### Run the full suite (Automatic Selection)

Runs the portable tests plus whatever directories match the host operating system:

```sh
just test
# OR
repro build io-mon:test
# OR
nimble test
```

### Run only portable tests

```sh
nimble testPortable
```

### Run only host-platform specific tests

```sh
nimble testPlatform
```
