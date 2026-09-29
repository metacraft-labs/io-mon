# Linux host threads share a mutable producer view

Status: open. Source inspected at io-mon `98fc05d`, including dev `9c03325`;
the same producer path is present at `5e71adf`.

## Observed

`writer.nim` owns one process-global `SetProducer`. Linux host threads call
`appendFragmentRecord` concurrently: `recordLock` protects only sequence-number
assignment. The producer's shared-memory entries are atomic, but its local
`ShmGSet.shards` sequence is not. `openShard` can grow that sequence and replace
its backing allocation from two threads simultaneously. The fork-child hook
also detaches and reconstructs the inherited view.

RunQuota's real subprocess fixture at `8631534` intermittently aborts with
heap corruption under both old and current Linux shims; native runs pass.
Compiler-policy changes alone do not repair it. GDB with file transport passes
three repetitions at shared `fc7895d`. These observations motivate a shared-
memory control; they do not yet attribute that fixture's corruption to this
race. Controls `36643557349` and `36643848013` retain the real shared-memory
host and compare serialization of the producer calls on the identical binary.

## Expected and repair contract

[Shim build policy](../docs/contributors/shim-build-policy.md#build-settings)
requires capturing every host thread without changing the host's execution.
[Transport lifecycle](../docs/contributors/event-transport-and-loss-freedom.md)
requires durable shared-memory publication before returning from a hook.
A lock-free shared table does not make its process-local mapping list safe for
concurrent mutation.

Serialize access to the shared local producer view, including mapping growth.
Coordinate fork with the same lock: prepare waits for publication to finish,
and parent/child release their copy before further capture or child reattach.
Keep capture muting around publication so allocator/file hooks do not reenter
the lock. Preserve the shared-memory protocol, loss reporting, native behavior
and all fixture deadlines. Record the cost as process-local serialization;
separate processes still publish through the shared table's atomic protocol.

Validate with the unchanged failing RunQuota executable and a real pthread
fixture that forces shard growth, checks every distinct observed path, and
forks while workers run. The old source must fail a positive control; the repair
must preserve complete capture and finish within the same timeout. Do not
substitute the file transport or weaken corruption/completeness assertions.

Fetched dev `9c03325`, searched live issues and deleted issue history, and
searched producer/thread/shard race commits before filing. RunQuota's existing
heap-corruption issue records the consumer failure.
