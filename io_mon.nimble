# Package

version       = "0.1.0"
author        = "Metacraft Labs"
description   = "Cross-platform filesystem I/O monitoring for Nim (relocation of reprobuild's fs-snoop stack) on nim-stackable-hooks."
license       = "MIT"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
#
# io-mon builds on nim-stackable-hooks (the interpose framework, package name
# `stackable_hooks`). In this `repo`-managed multi-repo workspace, sibling
# checkouts are resolved by path — consistent with the other Metacraft Nim
# siblings (nim-acp, nim-agents, codetracer-trace-format-nim), which likewise
# do NOT pin workspace siblings as Nimble git deps. The `--path` switch is
# supplied by the test task below (and by the documented `nim c -r --path:...`
# invocations), so no published `stackable_hooks` package is required.
#
# Deliberately NOT a git dependency: a `requires "https://…/nim-stackable-hooks"`
# would fight the sibling checkout the workspace already provides (pulling a
# second, divergent copy into ~/.nimble). CI runs from the workspace and uses
# the same sibling path.
requires "nim >= 2.0.0"

task test, "Run the io-mon test suite":
  # The sibling nim-stackable-hooks checkout is added to the path so the
  # `stackable_hooks/...` imports resolve without a published package.
  let hooksPath = "--path:../nim-stackable-hooks/src"
  exec "nim c -r " & hooksPath & " tests/test_io_mon_parity_with_fs_snoop.nim"
  exec "nim c -r " & hooksPath & " tests/test_io_mon_builds_standalone.nim"
  # The relocated interpose shim (io_mon/shim, io_mon/hooks) must build as a
  # drop-in `librepro_monitor_shim` shared library on nim-stackable-hooks with
  # no reprobuild path (this test invokes `nim c --app:lib` internally).
  exec "nim c -r " & hooksPath & " tests/test_io_mon_shim_builds_standalone.nim"
  # M8: the standalone io-mon CLI builds, is resolvable, and drives a live
  # capture over a freshly-built user binary (honestly documenting the macOS
  # chained-fixups interpose gap rather than faking a capture).
  exec "nim c -r " & hooksPath & " tests/test_io_mon_snoop_cli.nim"
  # macOS body-patch backend: positively captures a shared-cache-internal open
  # (fopen → libsystem-internal open$NOCANCEL) that __DATA,__interpose misses,
  # and asserts the interpose-only contrast. macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_bodypatch.nim"
  # macOS body-patch SPAWN family: proves injection PROPAGATES through a
  # shared-cache-internal (dylib-originated) spawn the interpose section misses
  # (spec §16.7.8), with the both-vs-interpose contrast. macOS-only (no-op
  # pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_bodypatch_spawn.nim"
  # macOS record-once regression: under the DEFAULT `both` backend a single
  # direct stat()/posix_spawn() must produce EXACTLY ONE record each — locking in
  # the fix that unified the interpose + body-patch hook sets (the old duplicated
  # hooks double-recorded under `both`). macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_record_once.nim"
  # macOS GENUINE system() SIP-child capture (the previously-BLOCKED test): a
  # `system("/bin/sh -c 'cat /etc/services >/dev/null'")` probe under the shim
  # with CT_SANDBOX_TOOLS_DIR pointed at the non-SIP drop-in bundle
  # (scripts/build-sandbox-tools.sh) — the SIP /bin/sh AND /bin/cat are
  # redirected to injectable drop-ins that RUN (not AMFI-killed) and the read of
  # /etc/services IS captured, with the present-vs-absent contrast. macOS-only;
  # skips cleanly if no runnable non-SIP sh/cat drop-in resolves (no-op pass
  # elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_sip_system_child.nim"
  # macOS body-patch RESOLUTION (the keystone): the installer resolves every
  # target to the REAL libsystem (skipping the shim's own __interpose wrappers),
  # so the install banner reports failed=0 and the fork/posix_spawn(p)
  # trampolines all build (*_tramp=ok). Locks in the dlsym-resolves-to-shim fix
  # that was corrupting the shim's own code (SIGTRAP). macOS-only (no-op pass
  # elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_bodypatch_resolution.nim"
  # macOS rename/renameat hooks: the gnulib/autotools atomic-output move
  # (`chmod a-w $@t; mv $@t $@`) is RECORDED as a destination write AND still
  # WORKS under the body-patch (it must not break the move). macOS-only (no-op
  # pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_rename.nim"
  # macOS body-patch VARIADIC open-mode forwarding: with both mechanisms on (the
  # default) a libsystem-internal `fopen("…","w")` (whose `open$NOCANCEL` passes
  # `mode` on the STACK per the arm64 Apple variadic ABI) must create the file
  # with the CORRECT mode (0644), readable back — locking in the fix for the
  # body-patch nimcache `Permission denied` defect (the old fixed-3-arg
  # body-patch hook read `mode` from x2/garbage). macOS-only (no-op pass
  # elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_bodypatch_open_mode.nim"
  # macOS threaded-write capture: a write issued from a NON-MAIN (pthread_create'd)
  # thread that exits before process teardown must still produce an `mrFileWrite`
  # record. The per-thread fragment batch is flushed SYNCHRONOUSLY in the emit
  # path for worker threads (a pthread thread-exit destructor can't flush — macOS
  # tears down a non-Nim thread's Nim TLS before it runs). Locks in the
  # threaded-write capture-gap fix under both backends. macOS-only (no-op pass
  # elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_threaded_write.nim"
  # T0 earned-completeness (adversarial hardening): unit coverage for the
  # unmonitored-subtree downgrade algorithm on synthetic record sets (platform-
  # independent; fast). An un-injected spawn child or an exec/SETEXEC into an
  # un-injectable image yields one event-loss → mcIncomplete.
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_t0_completeness.nim"
  # macOS T2 content/metadata hooks (adversarial hardening #3/#5): a clonefile /
  # hardlink / copyfile-CLONE source is recorded as a read, and a getattrlist
  # existence probe as a path-probe — the CoW/metadata dependencies the open/read
  # and stat hooks miss. macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_content_hooks.nim"
  # macOS symlink + /.vol target resolution (adversarial hardening #7,
  # mcapSymlink): a hooked open of a symlink / inode firmlink ALSO records the
  # fcntl(F_GETPATH)-resolved real target. macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_symlink.nim"
  # macOS POSIX_SPAWN_SETEXEC recording + env override (T1) and the earned-
  # completeness downgrade (T0): a SETEXEC records+flushes its exec BEFORE the
  # non-returning forward; an empty caller DYLD is overridden so the child is
  # injected; a SETEXEC/spawn into an un-injectable image downgrades to
  # mcIncomplete. macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_setexec.nim"
  # macOS T3a IPC / daemon-over-socket breakaway (adversarial hardening #1): the
  # CRITICAL escape that DEFEATS the subtree fail-safe. A persistent daemon
  # started OUTSIDE the invocation reads files on a monitored client's behalf over
  # an AF_UNIX socket. The connect(2) hook records the peer pid; the merge
  # downgrades to mcIncomplete when the peer is out-of-tree (regression: was
  # mcComplete), keeps mcComplete for intra-tree IPC (the cardinal-sin guard), and
  # — via a cooperating daemon's breakaway report (BuildXL Trusted-Tools prior
  # art) — keeps mcComplete WITH the daemon-read file folded in. macOS-only (no-op
  # pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_ipc_breakaway.nim"
  # macOS T3b library-load / dependent-dylib + dlopen capture (adversarial
  # hardening #4 + the dlopen arm of #7): dyld maps an executable's dependent
  # dylibs — and dlopen'd images — via low-level kernel mmap, bypassing the hooked
  # open/openat (a real clang/ld64 link loaded 620 dylibs while io-mon recorded
  # 0). The shim's `_dyld` add-image callback now records each non-system,
  # real-on-disk dylib as a library-load content dependency; an aggressive filter
  # drops the ~600-image system baseline. Asserts the dlopen'd plugin and a
  # /tmp-built dependent dylib are captured while libSystem is NOT (no flood).
  # macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_library_load.nim"
  # macOS ROUND-2 phase R-B: four content/metadata hook-coverage false-negatives
  # closed against the round-2 adversarial corpora — R3 (a pure O_RDWR open is an
  # INPUT, not collapsed to a write, so an O_RDWR-opened-then-read config is not
  # dropped from the inputs), R4 (the stat/lstat/fstatat/access family ALSO records
  # the realpath-canonical companion and stamps (dev, ino) for hardlink identity,
  # so a `/./`-laden / mid-symlink / relative-after-chdir metadata dependency stays
  # matchable), R6 (the library-load self-exclusion is by mach_header / exact
  # realpath identity, not a substring, so a dependency dylib whose path merely
  # CONTAINS "librepro_monitor_shim" is recorded), and R9 (a MAP_SHARED|PROT_WRITE
  # mmap write-back is recorded as a content write the bare open does not convey).
  # macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_round2_rb.nim"
  # macOS ROUND-2 phase R-D: NON-FILE determinism inputs (round-2 break R10) — a
  # build whose output depends on a non-file input that changed produces a
  # byte-identical depfile (a false cache hit a file-monitor cannot see). Handled by
  # a THREE-WAY split: env vars / sysctl / uname are OBSERVED DECLARED INPUTS
  # (recorded, folded into the consumer's cache key — BuildXL observed-environment
  # model — NO downgrade); getentropy / arc4random* / a /dev/urandom read are
  # AUTO-DOWNGRADED (non-deterministic ⇒ always re-run); clock_gettime / gettimeofday
  # / time / mach_absolute_time are RECORDED-not-downgraded (almost every program
  # times a loop benignly — flagging that would re-run everything, the cardinal sin).
  # The cardinal-sin guard (env/time stay mcComplete; ONLY randomness downgrades) is
  # the key correctness property. Proven live against the r2_implicit corpus
  # (minicc.c / readfile.c) plus platform-independent merge tests. macOS-only.
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_rd.nim"
  # T3c EndpointSecurity backend SKELETON (adversarial hardening #6, the residual
  # raw-syscall / XPC gap the in-process interpose backend structurally cannot
  # see): unit coverage for the pure, SDK-free logic the production ES backend is
  # built on — the process-subtree filter (ES is system-global; keep only the
  # build's root pid + FORK/EXEC descendants), the global_seq_num event-loss
  # detector (a drop → mrEventLoss → mcIncomplete, reusing the T0 machinery), and
  # the ES-event → existing-RMDF-record mapping (no new wire-format enum). Also
  # asserts the default-build backend is an HONEST design stub (refuses to start).
  # The entitlement-restricted ES client is behind the off-by-default
  # `-d:ioMonEndpointSecurity` define and is NOT exercised here. Platform-
  # independent. See reprobuild-specs/MacOS-EndpointSecurity-Backend.md.
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_endpoint_security.nim"
  # macOS ROUND-2 phase R-C: close the XPC / Mach-port breakaway false negative
  # (round-2 break R2), the CRITICAL escape that DEFEATS the connect(2) breakaway
  # fail-safe. XPC and raw Mach RPC never issue connect(2) — a client resolves a
  # service name to a Mach send port via bootstrap_look_up (raw Mach) or
  # xpc_connection_create_mach_service (XPC) + mach_msg — so a monitored client
  # that delegates a file read to an out-of-tree service produced a false
  # mcComplete. R-C hooks the connection-establishment boundary: a resolution of a
  # NON-com.apple.* service records an mrIpcConnect with an unknown
  # (launchd-brokered) peer pid, which the merge downgrades to mcIncomplete via
  # the EXACT T3a machinery. Asserts: the raw-Mach r2_xpc escape now downgrades
  # (was mcComplete; best-effort, skips if the host forbids raw Mach bootstrap),
  # the XPC create-entry path downgrades environment-independently, and — the
  # CRITICAL no-false-downgrade guard — a trivial program AND a com.apple.*-only
  # program both stay mcComplete (the shim's own startup bootstrap calls must not
  # self-downgrade every capture). macOS-only (no-op pass elsewhere).
  exec "nim c -r " & hooksPath & " --path:src tests/test_io_mon_macos_xpc_mach_breakaway.nim"

task buildShim, "Build the io-mon interpose shim shared library":
  # Produces build/lib/librepro_monitor_shim.{dylib,so,dll} — the drop-in
  # shared-library name reprobuild's M7 swap and io-mon's own fs_snoop locate.
  exec "scripts/build_shim.sh"

task buildSnoop, "Build the io-mon standalone CLI binary":
  # Produces build/bin/io-mon — the standalone snoop entry point on PATH
  # (a relocation of reprobuild's `repro internal io monitor` subcommand). It
  # runs a command under the interpose shim and writes the captured RMDF
  # depfile, so out-of-process consumers (the CodeTracer incremental test
  # runner's live read-file capture) can drive a live capture in a clean
  # subprocess.
  #
  # The snoop CLI depends only on io-mon's own modules + nim-stackable-hooks
  # (fs_snoop's interpose driver imports it); the sibling checkout is added to
  # the path the same way the test task does, so no published package is needed.
  let hooksPath = "--path:../nim-stackable-hooks/src"
  exec "nim c " & hooksPath & " --path:src --threads:on " &
    "--out:build/bin/io-mon cmd/io_mon_snoop.nim"
