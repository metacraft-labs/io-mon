---
title: Environment Variables
description: Reference guide for io-mon operator overrides, runtime variables, and debug diagnostics.
section: reference
order: 3
---

# Environment Variables

This document lists the environment variables recognized by the `io-mon` CLI, driver, and interception shims.

---

## Operator Variables

These variables are intended for operators, system integrators, and package maintainers:

| Variable                      | Description                                                                                                                                                                                                                                                                     |
| :---------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `REPRO_MONITOR_SHIM_LIB`      | Explicit path to the `io-mon` interposition shared library (`librepro_monitor_shim.so` / `.dylib` / `.dll`). When set, `io-mon` uses this path exclusively. If set to a non-existent path, `io-mon` fails immediately with an error rather than falling back to auto-discovery. |
| `CT_SANDBOX_TOOLS_DIR`        | macOS only. Directory containing non-SIP replacement binaries for protected utilities (`sh`, `cat`, etc.). If unset, `io-mon` dynamically creates a temporary drop-in directory during execution.                                                                               |
| `IO_MON_BREAKAWAY_REPORT_DIR` | Directory where cooperating background daemons deposit out-of-band file access reports. `io-mon` reads these reports and merges the observations into the final depfile.                                                                                                        |

---

## Driver & Runtime Variables

These variables are automatically configured by the `io-mon` driver when launching child process trees. You typically do not need to set them manually:

| Variable                           | Description                                                                                             |
| :--------------------------------- | :------------------------------------------------------------------------------------------------------ |
| `REPRO_MONITOR_APP_ID`             | Scopes shared memory segments to prevent cross-application collision. Defaults to `"io-mon"`.           |
| `REPRO_MONITOR_FRAGMENT_DIR`       | Working directory where per-process and per-thread lock-free event fragments are staged prior to merge. |
| `REPRO_MONITOR_OUTPUT`             | Target path where the final canonical `.iomon` depfile will be created.                                 |
| `REPRO_MONITOR_SESSION`            | Unique UUID identifying the current capture session.                                                    |
| `IO_MON_LINUX_DESCENDANT_GRACE_MS` | Milliseconds to wait before checking for detached orphan processes on Linux. Defaults to `500`.         |

---

## Debug Diagnostic Variables

These options are active **only** when running a debug-compiled shim (`IO_MON_BUILD_MODE=debug`). In release builds, they are compiled out as no-ops:

| Variable                         | Description                                                                             |
| :------------------------------- | :-------------------------------------------------------------------------------------- |
| `IO_MON_DEBUG_DISABLE_BODYPATCH` | Disables function body patching on macOS, falling back exclusively to `DYLD_INTERPOSE`. |
| `IO_MON_DEBUG_DISABLE_INTERPOSE` | Disables dynamic linker interposition, testing body patching isolation.                 |
| `IO_MON_DEBUG_SKIP`              | Comma-separated list of hook function names to deliberately bypass for A/B debugging.   |
