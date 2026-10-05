---
title: io-mon docs
description: io-mon is a cross-platform filesystem and process monitoring library and CLI with provable completeness guarantees for incremental builds.
order: 1
---

# io-mon

:::hero title="io-mon"
:::button href="/getting_started" variant="primary"
Get Started
:::button href="https://github.com/metacraft-labs/io-mon" variant="secondary"
GitHub
:::

## Overview

`io-mon` is a cross-platform filesystem and process monitoring library and command-line tool. It tracks the exact files read, written, and probed by a monitored process tree, exporting them to a compact, canonical binary depfile (`.iomon`).

Incremental build systems and test runners (such as `reprobuild` and `CodeTracer`) use `io-mon` to detect precise action dependencies with an **honest completeness guarantee**: if any access could not be observed reliably (e.g. hardened binaries, unmonitored daemons, or event loss), `io-mon` immediately flags the capture as incomplete (`mcIncomplete`), allowing consumers to fail-safe and re-execute.

## Key Capabilities

- **Deep Process Tree Interception**: Follows process lifecycles across forks, execs, and spawns on macOS, Linux, and Windows.
- **Exhaustive File & Dependency Capture**: Records file opens, reads, writes, directory enumerations, path existence probes (`stat`/`access`), dynamic library loads (`dlopen`), and shared memory write-backs (`mmap`).
- **Honest Completeness Signal**: Every depfile carries a provable `completeness` status (`mcComplete` or `mcIncomplete`). Consumers never rely on false cache hits from unmonitored children or dropped events.
- **Flexible Evidence Scope**: Choose between `full` evidence (recording every lookup, including failed existence checks) and `reads-only` evidence (recording successful reads only, matching compiler-emitted depfile semantics).
- **Public Batch & Decomposed APIs**: Drive monitoring through the command-line CLI (`io-mon run` / `io-mon inspect`), the synchronous batch library call (`runMonitored`), or non-blocking event-loop polling (`startMonitor` / `pollMonitor` / `finishMonitor`).

## Start here

:::cards
:::card title="Getting Started" icon="/assets/img/icon**start.svg" href="/getting_started"
Understand io-mon's design and guarantees, install the CLI across multiple package managers, and run your first capture.
:::card title="Guides" icon="/assets/img/icon**components.svg" href="/guides"
Learn how to wrap real builds, stream live events, choose the right evidence scope, and integrate the library into Nim applications.
:::card title="Reference" icon="/assets/img/icon\_\_style.svg" href="/reference"
Comprehensive reference for the `io-mon` CLI flags, binary depfile format specifications, record kinds, and environment variables.
:::

## Popular articles

:::cards variant="compact"
:::card title="Overview & Architecture" href="/getting_started/overview"
Getting Started
:::card title="Installation" href="/getting_started/installation"
Getting Started
:::card title="Quickstart" href="/getting_started/quickstart"
Getting Started
:::card title="Monitoring Builds" href="/guides/monitoring-builds"
Guides
:::card title="Evidence Scope & Hazards" href="/guides/evidence-scope"
Guides
:::card title="CLI Reference" href="/reference/cli-reference"
Reference
:::
