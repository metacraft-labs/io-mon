---
title: CLI Reference
description: Complete command-line flag and option specification for io-mon run and io-mon inspect.
section: reference
order: 1
---

# CLI Reference

The `io-mon` binary provides two main subcommands: **`run`** (for executing and capturing command trees) and **`inspect`** (for rendering existing depfiles).

---

## `io-mon run`

Executes a command under the interposition shim, traces all filesystem and process activity across its child hierarchy, and saves the resulting depfile.

```bash
io-mon run [options] -- <command> [args...]
```

> **Compatibility**: The `run` verb is optional; running `io-mon --depfile <out> -- <command>` functions identically.

### Options

| Flag                   | Argument      | Description                                                                                                                                                                     | Default          |
| :--------------------- | :------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------------- |
| `--depfile`            | `PATH`        | Path where the output binary `.iomon` file will be written. If omitted, a temporary file is used and discarded after rendering.                                                 | (temporary file) |
| `--events`, `--format` | `MODE`        | Live event streaming format. Supported modes: `none`, `text`, `jsonl`, `binary`, `binary-stream`.                                                                               | `none`           |
| `--event-stream`       | `PATH`        | Destination file or FIFO for live events instead of `stderr`. **Mandatory** when mode is `binary` or `binary-stream`.                                                           | `stderr`         |
| `--interest`           | `TOKENS`      | Comma-separated subset of event categories to record: `file-reads`, `path-probes`, `file-writes`, `proc`, `lib`, `env`, `entropy`, `ambient`. Omitting captures all categories. | (all categories) |
| `--evidence`           | `SCOPE`       | Evidence scope level: `full` (records all lookups including failed probes) or `reads-only` (records successful reads/opens only).                                               | `full`           |
| `--capture-stdio`      | _(none)_      | Captures child `stdout` and `stderr` in memory instead of inheriting standard I/O streams.                                                                                      | Disabled         |
| `--capture-stdio-path` | `PATH`        | Writes captured child standard I/O streams to `PATH` (implies `--capture-stdio`).                                                                                               | None             |
| `--`                   | _(delimiter)_ | Mandatory delimiter indicating the start of the command and arguments to monitor.                                                                                               | _(required)_     |

Both `--option value` and `--option=value` syntax forms are accepted.

---

## `io-mon inspect`

Decodes and displays the contents of a previously captured `.iomon` binary depfile.

```bash
io-mon inspect <depfile> [--format text|json]
```

### Options

| Flag                   | Argument | Description                                                                                | Default |
| :--------------------- | :------- | :----------------------------------------------------------------------------------------- | :------ |
| `--format`, `--events` | `MODE`   | Output format: `text` (human-readable table) or `json` (machine-readable structured JSON). | `text`  |

> **Note**: `jsonl` is a streaming mode for `run --events jsonl`, and is not supported by `inspect`.

---

## Exit Codes

- **Monitored Child Exit**: When monitoring finishes successfully, `io-mon` exits with the **exact exit code of the monitored root process**.
- **Internal Monitoring Errors**: If `io-mon` fails to initialize the shared memory transport, cannot resolve the shim library, or encounters unrecoverable configuration errors, it writes a diagnostic message to `stderr` and terminates with a non-zero exit code.
