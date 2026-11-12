# The Linux shim records no in-tree creation for `socket(2)`, so a socket read through an inherited descriptor number downgrades

|             |                                                                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                                                                                                  |
| Recorded    | 2026-11-07                                                                                                                                                            |
| Observed in | io-mon @ `3d47bb1` plus the change that records the AF_INET destination and failed connects; x86_64 Linux                                                             |
| Area        | `src/io_mon/shim/linux_preload.nim` (`recordLocalFdCreate`, `classifyEmptyFdRead`), `src/io_mon/hooks/linux_preload_runtime.nim` (no `socket`/`accept` interposition) |

## Observed

A monitored bash that opens a TCP connection itself and reads the reply with
a redirection —

```bash
exec 4<>"/dev/tcp/127.0.0.10/4100"
read -r line <&4
```

— is graded `mcIncomplete` on Linux with the loss "out-of-tree content
channel consumed (POSIX shm not created in-tree, FIFO with no in-tree
writer, or an inherited pipe/socket with no in-tree create)". The same
script on macOS is complete. `read -r -u 4 line` (no redirection) is
complete on Linux too.

Cause: for `<&4` bash `dup2`s the socket onto fd 0. Fd 0 was open when the
shim initialised, so `classifyEmptyFdRead` treats the read as an INHERITED
descriptor and records `chan=opaque role=read` with the socket's
`(dev,ino)`. The merge pairs such a read against an in-tree
`chan=localfd role=create` of the same object, but the Linux shim
records creates only for `pipe`/`pipe2`/`socketpair`/`eventfd`/`timerfd`/
`memfd` — not for `socket(2)` or `accept(2)` — so the socket the tree
created itself stays unpaired and downgrades. The macOS shim records every
in-tree local-IPC fd creation, `socket` and `accept` included, so the
platforms disagree.

## Expected

A socket the monitored tree created (or accepted) pairs like a pipe it
created: a read of it through any descriptor number is not an out-of-tree
content channel. Its remote peer, if out of tree, is already judged by the
`mrIpcConnect` arm (signal (c)). Interposing `socket` and `accept`/`accept4`
on Linux and calling `recordLocalFdCreate` on success, as macOS does, would
make the two shims consistent.

## Impact

Found by a consumer's network test: a monitored script that reads the reply
from a server it connected to through `<&4` is graded incomplete on Linux, so
a capture that is in fact complete cannot be trusted. The test works around
it by reading with `read -u 4`.
