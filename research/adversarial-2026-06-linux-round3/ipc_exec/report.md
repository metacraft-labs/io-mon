# io-mon Linux IPC/exec-boundary adversarial probe report

Target: `/home/zahary/m/dev/io-mon-hardening-work` at `d2c451d5e009cc6ccd74b5eb5388e2b525825651`

Artifacts:
- CLI: `/tmp/io_mon_campaign_ipc_exec/bin/io-mon`
- Shim: `/tmp/io_mon_campaign_ipc_exec/lib/librepro_monitor_shim.so`
- Probe sources: `/tmp/io_mon_campaign_ipc_exec/src/`
- Depfiles: `/tmp/io_mon_campaign_ipc_exec/runs/*.rdep`
- Rendered inspections/stdout/stderr: `/tmp/io_mon_campaign_ipc_exec/logs/`

Harness smoke:
- `baseline_openread`: normal `open`/`read` of marker.
- Result: marker present, `completeness=mcComplete`.
- Evidence: `/tmp/io_mon_campaign_ipc_exec/logs/baseline_openread.inspect`.

Confirmed breaks:

1. Persistent Unix-socket daemon reads marker out of process
- Probe: daemon started outside io-mon; monitored client sends marker path over `AF_UNIX` socket and hashes returned bytes.
- Client output depends on marker bytes:
  `/tmp/io_mon_campaign_ipc_exec/logs/unix_ipc.stdout`
- Depfile:
  `/tmp/io_mon_campaign_ipc_exec/logs/unix_ipc.inspect`
- Result: marker absent, `completeness=mcComplete`.
- Notes: depfile records socket `file-read` entries with empty path, but no `mrIpcConnect`/downgrade. The rendered backend profile explicitly has an optional `ipc-connect` capability gap: Linux preload does not hook `connect(2)`.

2. Persistent loopback-TCP daemon reads marker out of process
- Probe: daemon started outside io-mon; monitored client connects to `127.0.0.1:<port>`, sends marker path, and hashes returned bytes.
- Client output depends on marker bytes:
  `/tmp/io_mon_campaign_ipc_exec/logs/tcp_ipc.stdout`
- Depfile:
  `/tmp/io_mon_campaign_ipc_exec/logs/tcp_ipc.inspect`
- Result: marker absent, `completeness=mcComplete`.
- Notes: same failure mode as Unix socket. This is expected from the source inspection: shared merge logic can downgrade `mrIpcConnect`, but Linux live preload does not emit `mrIpcConnect`.

Caught attempts, not breaks:

1. libc `execve` with scrubbed environment
- Probe: `/tmp/io_mon_campaign_ipc_exec/bin/exec_env_scrub`.
- Result: marker absent, `completeness=mcIncomplete`.
- Depfile includes event-loss records, so a consumer would rerun.

2. raw `syscall(SYS_execve)` with scrubbed environment
- Probe: `/tmp/io_mon_campaign_ipc_exec/bin/raw_exec_env_scrub`.
- Result: marker absent, `completeness=mcIncomplete`.
- Root-process completeness guard catches the missing monitored root/start evidence.

3. raw direct invocation of the ELF dynamic loader with scrubbed environment
- Probe: `/tmp/io_mon_campaign_ipc_exec/bin/ldso_direct_exec`.
- Loader path recorded in `/tmp/io_mon_campaign_ipc_exec/logs/ldso.path`.
- Result: marker absent, `completeness=mcIncomplete`.
- Root-process completeness guard catches the missing monitored root/start evidence.

Not runnable here:
- Static binary exec-boundary probe. `cc -static` failed because this Nix shell does not provide static libc (`/tmp/io_mon_campaign_ipc_exec/logs/static-build.log`).

Incidental harness note:
- A first `fopen`/`fread` baseline did not capture the marker. The current Linux shim captures `open`/`read` reliably, which was used for the confirmed probes.
