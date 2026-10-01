# Windows IPC relative-path fixture loses its shim after changing directory

Status: open. Observed at `13d12f3` in Windows x64 Reprobuild
[job 110470523118](https://github.com/metacraft-labs/io-mon/actions/runs/36892096089/job/110470523118).

The monitored graph and repeated isolated programs succeed, but the native
`just test` cross-check fails the relative `pipe\\notapipe.txt` case in
`test_io_mon_windows_ipc_connect`. Its executable lives under `tests/windows`,
and changing cwd to its temporary directory removes the repo-root shim discovery
candidate. `runMonitored` raises `cannot find librepro_monitor_shim.dll` before
exercising the path classifier. The surrounding absolute-path cases succeed.

The fixture must resolve the real product DLL before changing directory and
restore any previous override after the case. Preserve the relative spelling,
actual file access, empty IPC records and complete-capture assertions. The
expectation comes from `docs/usage.md` (Windows live capture) and the fixture's
M4 IPC identity contract; `shim_discovery.nim` documents its cwd-relative search.

GitHub reports the native cross-check and job as successful despite Nimble's
failure output. This is a separate exit-propagation finding still being traced;
a green job status alone cannot validate this test at the observed revision.

Fetched `agents` / `dev` at `e0dfabd` / `2d07041`, and searched current and
archived issues for Windows shim discovery, relative paths and cross-check exit
status before filing. Evidence: `/tmp/io-mon-13d-windows-x64-repro.log`.
