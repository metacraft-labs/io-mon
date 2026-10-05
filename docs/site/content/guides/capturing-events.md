---
title: Capturing & Streaming Events
description: Live event streaming modes (text, jsonl, binary) and event category filtering with interest tokens.
section: guides
order: 2
---

# Capturing & Streaming Events

While `io-mon` primarily writes canonical `.iomon` files upon completion, it can also stream observed events live as they occur.

---

## Streaming Modes

The `--events` option (aliased as `--format`) controls live event streaming:

```bash
io-mon run --events <MODE> [options] -- <command>
```

Available modes:

- **`none` (Default)**: No live streaming; events are buffered internally and written to the depfile at termination.
- **`text`**: Emits human-readable lines as events are processed.
- **`jsonl`**: Streams newline-delimited JSON objects, ideal for piping into observability pipelines, log forwarders, or interactive GUIs.
- **`binary`** / **`binary-stream`**: Streams raw binary event frames.

### Redirecting the Stream (`--event-stream`)

By default, `text` and `jsonl` streams are written to `stderr` so they do not interfere with the monitored command's standard output.

To redirect the event stream to a separate file or named pipe (FIFO):

```bash
io-mon run --events jsonl --event-stream /tmp/events.jsonl --depfile build.iomon -- ninja
```

> **Important**: When using `binary` or `binary-stream`, `--event-stream PATH` is **mandatory** to prevent raw binary corruption of terminal output.

---

## Event Interest Filtering (`--interest`)

By default, `io-mon` captures all supported event types. If your consumer only cares about a subset of operations (for instance, tracking file writes for indexing, or process spawning for process trees), you can pass an explicit comma-separated list of interest tokens:

```bash
io-mon run --interest file-writes,proc -- ninja
```

### Supported Categories

| Token         | Captures                                                                             |
| :------------ | :----------------------------------------------------------------------------------- |
| `file-reads`  | File open/read operations (`open`, `read`, `pread`).                                 |
| `path-probes` | File existence checks and metadata queries (`stat`, `lstat`, `access`).              |
| `file-writes` | File creation, modification, truncation, and deletion (`write`, `unlink`, `rename`). |
| `proc`        | Process lifecycle events (`fork`, `execve`, `spawn`, `exit`).                        |
| `lib`         | Dynamic library loading (`dlopen`, `LoadLibraryW`).                                  |
| `env`         | Environment variable accesses.                                                       |
| `entropy`     | Reads from random number sources (`/dev/urandom`, `getrandom`).                      |
| `ambient`     | Clock reads, hostname lookups, and host identity queries.                            |

### Filter Semantics & Safety

- **Omitting `--interest` means all categories**: If the flag is omitted or empty (`--interest ""`), `io-mon` captures everything. Forgetting the flag only costs slightly more capture work, never a missed dependency.
- **Validation**: Specifying only unknown tokens is refused with an error to prevent silent filtering mistakes. Unknown tokens alongside valid ones are ignored to support forward compatibility across `io-mon` versions.
- **Legacy spellings**: Pre-DA-5 tokens (`file`, `proc`, `lib`, `nondet`, `ipc`) remain supported and expand to their modern category equivalents.
