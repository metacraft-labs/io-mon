# macOS worker threads retain fragment descriptors after exit

|             |                                                                           |
| ----------- | ------------------------------------------------------------------------- |
| Status      | in-progress; release repairs on `fix/macos-monitor-fixtures`              |
| Recorded    | 2026-09-28                                                                |
| Observed in | io-mon `de755e5e88748f8fd73ae233f0236d87aaacee15`; unchanged in `0e29ca7` |
| Area        | `macos_interpose.emitRecord`, fragment writer lifetime                    |

## Observed

RunQuota `1124b7f` plus its test-graph patch runs the same compiled
`t_observation_store_users` successfully without injection, but exits 127
with the macOS shim when RLIMIT_NOFILE is 1024. A real `lsof` sample before
failure counts 919 `.iomon-frag` handles in the root test process. The count
rises with short-lived worker threads. Raising only the limit to 4096 makes
all eight cases pass. The Nix shell inherits an unlimited descriptor limit,
which explains why its native test run concealed this defect.

`emitRecord` flushes worker batches synchronously because calling Nim from a
macOS pthread destructor is unsafe. It retains the cached FILE and registry
entry, however, after the worker's TLS is destroyed.

## Expected

[Shim build policy](../docs/contributors/shim-build-policy.md) requires an
injected observer to preserve the host's behavior and avoid teardown-time Nim
calls from foreign threads. The existing threaded-write capture contract in
`test_io_mon_macos_threaded_write` requires worker evidence to survive exit.
Descriptors must remain bounded by live activity, not all past threads.

## Evidence

Local control: Reprobuild `4adfd0e7` runs `internal io monitor --depfile ...
--interest file-reads,path-probes,file-writes,proc,lib,env,entropy,ambient
--evidence full -- build/test-bin/t_observation_store_users`, with
`REPRO_MONITOR_SHIM_LIB` pointing to the shim built from `de755e5`.
The copied shim SHA256 is
`e987a5b53bafe5d1cbdc1c8ab647138f3a6b4523b191123d7086106915350769`.
Only `ulimit -n 4096` changes the failing control into a pass.

Before filing, io-mon dev was fetched and verified as ancestor `279a17b`.
Open issues and deleted issue history were searched for worker fragments,
thread exit, descriptor leaks and EMFILE; no matching record was found.

## Planned repair

Close and unregister worker fragment handles synchronously after each emit,
while their TLS is valid. Preserve per-fragment byte accounting across these
reopens so the existing loss marker and byte cap remain effective. Keep the
main-thread batching path. Test real sequential pthread creation with a low
file-descriptor limit, verify bounded live descriptors and every worker's
write evidence, and demonstrate failure against the old shim. Re-run the four
RunQuota programs and the complete macOS monitor graph.
