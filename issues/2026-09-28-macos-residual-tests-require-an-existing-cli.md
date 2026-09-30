# macOS residual tests depend on an existing CLI build

- Status: open
- Observed in: `09b5e583054af2aac274d0a0a57721df4a293f67`

The clean macOS suite reaches the round-4 inherited-pipe test, then fails
because `build/bin/io-mon` does not exist. The round-5 helper also invokes
`nimble buildSnoop` without checking its exit status, so a stale binary can
hide a failed build. Local validation had such a binary; it did not prove
that these tests provision their prerequisites.

The documented `nimble test` entrypoint and the release validation plan in
metacraft-specs/infrastructure/gosti-io-mon-runquota-releases.md require the
suite to run from a clean checkout. Both fixtures now compile the real CLI
using the selected Nim compiler and the checkout's dependency configuration.
They require compilation success before launching it; their live pipe and
mmap assertions remain unchanged.

Evidence: [macOS suite at 09b5e58](https://github.com/metacraft-labs/io-mon/actions/runs/36427690912/job/108945611662).
Refreshed dev and agents and searched current and archived issues before
recording this prerequisite gap.
