---
title: Guides
description: Practical task-oriented guides for monitoring builds, streaming events, managing evidence scopes, and using the Nim library.
section: guides
order: 0
---

# Guides

Practical, task-oriented guides for using `io-mon` to trace real workloads, stream real-time events, manage evidence scope, and embed monitoring directly into applications.

- [Monitoring Builds](/guides/monitoring-builds) — wrapping compilers, build runners, shell scripts, capturing stdio, and handling exit statuses.
- [Capturing Events](/guides/capturing-events) — streaming events live over text, JSON Lines, or binary channels, and filtering event categories.
- [Evidence Scope & Hazards](/guides/evidence-scope) — understanding `full` vs `reads-only` evidence, the one-directional invalidation hazard, and compiler-depfile parity.
- [Library Usage](/guides/library-usage) — integrating `io_mon` into Nim programs via `runMonitored` and the decomposed host API (`startMonitor` / `pollMonitor` / `finishMonitor`).
