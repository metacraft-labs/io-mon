---
title: Quickstart
description: Step-by-step walkthrough of monitoring a build command, inspecting the depfile, and reading records in Nim.
section: getting_started
order: 3
---

# Quickstart

This walkthrough guides you through capturing the dependencies of a build command, inspecting the output, and consuming the results programmatically in Nim.

---

## 1. Verify Installation

Verify that the `io-mon` binary is accessible on your `PATH`:

```bash
io-mon --help
```

---

## 2. Capture a Build Command

Use `io-mon run` to monitor an arbitrary command. The `--depfile` option designates where the binary `.iomon` file is saved, and `--` separates the options from the monitored command:

```bash
io-mon run --depfile build.iomon -- gcc -c main.c -o main.o
```

During this execution:

1. `io-mon` sets up an isolated shared-memory transport and injects its interception shim.
2. The `gcc` process runs normally, reading headers, loading compiler passes (`cc1`), and generating `main.o`.
3. Descendant processes and threads emit observations into lock-free buffers.
4. On exit, `io-mon` merges fragments, validates completeness, and serialises `build.iomon`.

---

## 3. Inspect the Depfile

The `io-mon inspect` command translates binary `.iomon` files into human-readable text:

```bash
io-mon inspect build.iomon
```

Output:

```text
iomon version=1 records=8 completeness=mcComplete
#0 mrProcessStart pid=41230 tid=1
#1 mrFileRead pid=41230 tid=1 path=/usr/include/stdio.h
#2 mrFileRead pid=41230 tid=1 path=/usr/include/sys/cdefs.h
#3 mrProcessSpawn pid=41230 tid=1 childPid=41231
#4 mrProcessStart pid=41231 tid=1
#5 mrFileRead pid=41231 tid=1 path=/workspace/main.c
#6 mrFileWrite pid=41231 tid=1 path=/workspace/main.o
#7 mrProcessExec pid=41231 tid=1
summary records=8 processes=2 observations=6 eventLoss=0
```

To output structured JSON, pass `--format json`:

```bash
io-mon inspect build.iomon --format json
```

---

## 4. Consume in Nim

If you are developing a build tool or pipeline runner in Nim, use the `io_mon` library:

```nim
import std/logging
import io_mon

let dep = readMonitorDepFile("build.iomon")

if dep.completeness == mcComplete:
  echo "Provably complete capture:"
  for record in dep.records:
    case record.kind
    of mrFileRead, mrLibraryLoad:
      echo "  [INPUT]  ", record.path
    of mrFileWrite:
      echo "  [OUTPUT] ", record.path
    else:
      discard
else:
  warn "Incomplete capture! Invalidation required."
```

---

## Next Steps

- Learn how to wrap complex multi-process build pipelines in [Monitoring Builds](/guides/monitoring-builds).
- Explore live event streaming and category filtering in [Capturing Events](/guides/capturing-events).
- Understand the tradeoffs between full and reads-only evidence in [Evidence Scope & Hazards](/guides/evidence-scope).
