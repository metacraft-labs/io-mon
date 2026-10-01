# The FUP-H fd->path concurrency test makes no progress on a loaded Linux host

- Status: open
- Observed in: io-mon `4b2bb39` (`agents`) and `31b05a5`, NixOS x86_64-linux, 32 cores at load ~220

## Observed

`tests/linux/test_io_mon_shim_fd_path_concurrency.nim` ("io-mon shim fd->path
table cross-thread safety (FUP-H)") completed no case in 30 minutes, run
directly (`nim c -r --path:tests/helpers …`) at both revisions above, side by
side. In a full `just test` at 31b05a5 it was the only suite that stalled:
422 cases before it passed, 0 failed, and the run was cut off at 3 h inside it.

## Expected

A concurrency test either finishes or fails within a bound the test itself
states; a stall reads as a hang of the shim and blocks every later suite in
`just test`.

## Next step

Establish whether the stall is a real deadlock in the shim's fd->path table
(attach to the stalled process, dump thread stacks) or a test that scales its
work with load; then bound it with an explicit deadline that fails with the
state it reached.

Refreshed origin/agents; searched open issues and issue history for the test
name and "FUP-H" before recording.
