# macOS nested shims still hang during startup

Reopened on 2026-10-03 against `d3826a368e0ca8c2760bf5e3270cc3577811af47`,
macOS 26.5.2 ARM64, SIP enabled. The earlier issue was deleted by `0e29ca7`
after isolated test executions passed. Isolation qualified those fixtures;
it did not repair loading two distinct shim copies into one process.

## Expected behavior

The transparency and completeness contracts in
`docs/contributors/architecture.md` require a monitored program to retain its
behavior and uncertainty to be reported explicitly. Nested monitoring must not
hang a child before `main`. The authorized
[local follow-up requirements](https://github.com/metacraft-labs/metacraft-pm/blob/d731cdeae22cd2953dd8057bac3dbc3f4167ccd2/infrastructure/tool-release-local-followups.md)
require a bounded reproducer and preserved independent session evidence.

## Reproduction

Build the current production shim in a private directory, copy it to a second
path, and launch a real C reader with `DYLD_INSERT_LIBRARIES` containing both.
A single path and the same path twice both exit zero and read the fixture.
Two distinct paths time out after 15 seconds, with no stdout. The stack sample
is in `libSystem_initializer`, malloc's guarded-range initialization,
`repro_macos_real_arc4random_uniform_call` in one copy, and
`repro_macos_real_syscall` in the other. The diagnostic kills and reaps the child.
Local evidence: `/tmp/io-mon-nested-followup/results.log` and `distinct.sample`.

## Identified defect

`repro_wrap_syscall` declares fixed arguments. Apple's ARM64 calling convention
passes variadic arguments on the stack; a caller of `syscall(int, ...)` therefore
does not put the arguments in the registers this wrapper reads. A second shim's
entropy forwarding is one real caller. The current raw-syscall regression only
checks an incomplete verdict and discards the child's status and output, so it
cannot establish successful syscall forwarding.

Use the actual syscall ABI, including its seventh argument. Preserve errno and
wide return values, and keep the pre-initialization path free of allocation and
thread-local runtime state. Add controls for successful file operations, failure
errno and bounded two-copy startup. Startup success alone does not qualify
independent inner and outer monitor sessions.

Primary references:
[Apple ARM64 ABI](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)
and [libsyscall entry](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/custom/__syscall.s).

## Archive search

Fetched `origin/agents` and `origin/dev`, both `d3826a3`. Searched current issues
and deleted issue history for nested, macOS, entropy and initialization. The
archived issue at `368cc1c` records the same two-copy startup symptom; reopen it
instead of creating a duplicate.

## Startup repair and remaining session scope

The accompanying ABI repair passes the new real syscall and distinct-image
startup controls. Restoring the `a5fce6a` runtime makes the syscall control fail
and the distinct-image child time out; the strengthened older raw-syscall test
also rejects that runtime because its child exits 11 instead of reading the
file. Logs: `/tmp/io-mon-syscall-abi-tests.log` and
`/tmp/io-mon-syscall-negative-controls.log`.

The independent-session control launches a real monitor inside another monitor.
The inner session captures its input and is complete; the outer captures its
own input, lacks the inner child's reads, and reports a missing-process-start
loss marker. It terminates normally and remains honestly incomplete. The test
accepts a future complete outer capture only if it includes the inner input.
Full descendant evidence sharing remains open; the existing uncached fixture
isolation stays in place.
