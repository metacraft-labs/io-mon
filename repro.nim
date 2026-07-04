## Reprobuild project file for io-mon.
##
## io-mon is the cross-platform filesystem/process *observation* layer that
## reprobuild's build engine and CodeTracer's incremental test runner depend on
## (one-way: ``reprobuild → io-mon``, ``codetracer → io-mon``). This file lets a
## developer drive io-mon's build + test from reprobuild on any OS.
##
## ## Exposed build/test edges (what ``repro`` commands this file supports)
##
## From inside the io-mon checkout:
##
##   * ``repro build io-mon``        — build the ``default`` collection: the
##                                     standalone ``io-mon`` CLI binary
##                                     (``build/bin/io-mon`` /
##                                     ``build/bin/io-mon.exe``). Equivalent to
##                                     ``repro build`` (no positional target).
##   * ``repro build io-mon:shim``   — build the interpose shim shared library
##                                     ``build/lib/librepro_monitor_shim.{dylib,
##                                     so,dll}`` (the drop-in reprobuild's M7 swap
##                                     and io-mon's own ``fs_snoop`` locate).
##   * ``repro build io-mon:test``   — compile + run the full io-mon test suite
##                                     (wraps the existing ``nimble test`` task).
##
## From a *sibling* repo's working directory the same edges are reachable via the
## qualified ``io-mon:<target>`` selector (reprobuild materialises this file
## through ``repro_cli_support.findSiblingProjectFile``), e.g.
## ``repro build io-mon:shim``.
##
## ## Design notes — coarse-grained option-A wrapping
##
## Each edge wraps an *existing* build entry point verbatim with a ``shell(...)``
## action rather than re-deriving the build graph in the DSL:
##
##   * the shim (``scripts/build_shim.sh``) is an ``--app:lib`` shared-library
##     build with platform-specific arm64/arm64e fat-binary flags — a Mode-B
##     ("crude") shape per ``reprobuild-specs/Language-Conventions/Nim.md`` that
##     the fine-grained ``nim c --compileOnly`` Mode-A split cannot express, so a
##     faithful script wrap is the correct cut;
##   * the CLI (``nimble buildSnoop``) and the test suite (``nimble test``) both
##     resolve the sibling ``nim-stackable-hooks`` checkout through
##     ``--path:../nim-stackable-hooks/src`` and the test task is a NimScript
##     ``task`` block (also a Mode-B trigger), so they are wrapped one-for-one as
##     well.
##
## This is the same option-A approach runquota's ``repro.nim`` and the
## tcc-chain recipes take: preserve today's behaviour exactly, defer the
## per-translation-unit Mode-A graph to a follow-on milestone. The edges are
## additive — the ``io_mon.nimble`` ``buildShim`` / ``buildSnoop`` / ``test``
## tasks continue to work unchanged for non-engine builds.
##
## ## Sibling dependency: nim-stackable-hooks (NOT a nimble dep)
##
## io-mon builds on ``nim-stackable-hooks`` (package ``stackable_hooks``), a
## ``repo``-managed workspace sibling resolved BY PATH — it is deliberately NOT a
## nimble git dependency (see the rationale in ``io_mon.nimble``). The wrapped
## scripts add ``--path:../nim-stackable-hooks/src`` themselves; ``build_shim.sh``
## additionally honours ``$STACKABLE_HOOKS_SRC`` to override the sibling location
## when io-mon's source tree is read-only (Nix store path). A consumer driving
## these edges must therefore have the sibling checked out at
## ``../nim-stackable-hooks`` (or export ``STACKABLE_HOOKS_SRC`` for the shim).
## ## Validation
##
## Parses + type-checks under the DSL with::
##
##   nim check --path:<reprobuild>/libs/repro_project_dsl/src \
##             --path:<reprobuild>/libs/repro_dsl_stdlib/src ... repro.nim

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import repro_dsl_stdlib/packages/nim as nim_pkg
import ct_test_nim_unittest

package io_mon:
  uses:
    # Toolchain floor — mirrors ``io_mon.nimble``'s ``requires "nim >= 2.0.0"``
    # and the binaries the wrapped scripts shell out to. ``nimble`` drives the
    # ``buildSnoop`` / ``test`` tasks; ``sh`` runs ``scripts/build_shim.sh`` (a
    # bash script) and is the tool every ``shell(...)`` edge invokes.
    "nim >=2.0"
    "nimble"
    "sh"
    # The C-family compiler ``nim c`` shells out to for the C backend. macOS
    # builds (and the shim's arm64/arm64e fat link) use Apple ``clang``; Linux
    # and Windows (``--cc:gcc`` for the shim DLL) use ``gcc``. The user supplies
    # it via ``uses:`` per the Nim convention — it is not smuggled in implicitly.
    when defined(macosx):
      "clang"
    else:
      "gcc >=12"

  # The package itself — every ``.nim`` under ``src`` is importable when a
  # consumer expresses ``uses: "io-mon"``; ``src/io_mon.nim`` is the umbrella
  # re-export hub (types / capabilities / writer / reader / render / fs_snoop).
  library io_mon

  # The standalone CLI. The on-disk binary name is hyphenated (``io-mon``) but a
  # Nim identifier must be a valid ident, so it is declared ``ioMon`` with an
  # explicit ``name:`` override — the camelCase + ``name: "<hyphenated>"``
  # convention used across reprobuild's apps block and trace-format-nim's
  # ``ctPrint``. The actual compile is the explicit ``build:`` edge below
  # (the source lives at ``cmd/io_mon_snoop.nim``, outside ``srcDir``, so Mode-A
  # auto-recognition would never find it).
  executable ioMon:
    name: "io-mon"

  devEnv:
    task "bump-version", command = "nim r scripts/bump_version.nim", description = "Bump version number"

  build:
    const binSuffix = (when defined(windows): ".exe" else: "")
    const shimExt =
      when defined(windows): "dll"
      elif defined(linux): "so"
      else: "dylib"

    # ---- Shim shared library (``io-mon:shim``) -----------------------------
    #
    # Wraps ``scripts/build_shim.sh`` verbatim (the relocated counterpart of
    # reprobuild's ``build_apps.sh`` shim section). It selects the platform
    # entry point (``macos_interpose`` / ``linux_preload`` /
    # ``windows_interpose``), builds ``--app:lib`` with the macOS arm64+arm64e
    # fat flags, and emits the byte-identical drop-in
    # ``librepro_monitor_shim.<ext>``.
    let shimOutput = "build/lib/librepro_monitor_shim." & shimExt
    let shimBuild = shell(
      command = "scripts/build_shim.sh",
      actionId = "io-mon.shim.build_shim",
      extraInputs = @[
        "scripts/build_shim.sh",
        "src",
        "io_mon.nimble",
        "config.nims",
      ],
      extraOutputs = @[shimOutput])
    discard collect("shim", @[shimBuild])

    # ---- Standalone CLI (``io-mon`` / the ``default`` collection) -----------
    #
    # Compiles the standalone snoop binary directly.
    let cliOutput = "build/bin/io-mon" & binSuffix
    let cliBuild = nim.c(
      source = "cmd/io_mon_snoop.nim",
      binary = cliOutput,
      threadsOn = true,
      actionId = "io-mon.cli.build_snoop")
    # Enrol the CLI into the conventional ``default`` collection so a bare
    # ``repro build`` / ``repro build io-mon`` materialises it (see
    # ``repro_cli_support.DefaultBuildCollectionName``).
    discard collect("default", @[cliBuild])

    # ---- Test suite (``io-mon:test``) --------------------------------------
    #
    # Emits one compile-only BUILD edge + one EXECUTE edge per test file.
    # BUILD halves collect into ``test-builds``; EXECUTE halves collect into
    # ``test`` so ``repro test`` / ``repro build test`` materialise the runnable
    # closure (each execute edge transitively depends on its build edge, the CLI,
    # and the interpose shim).
    type
      TestSpec = object
        source: string
        binary: string

    var testBuildActions: seq[BuildActionDef] = @[]
    var testExecuteActions: seq[BuildActionDef] = @[]

    proc emitTestPair(source, binary: string;
                      buildActions, executeActions: var seq[BuildActionDef]) =
      var lastSlash = -1
      for i in 0 ..< binary.len:
        if binary[i] == '/' or binary[i] == '\\':
          lastSlash = i
      let stem =
        if lastSlash >= 0: binary[lastSlash + 1 .. ^1]
        else: binary
      let edge = buildNimUnittest.build(
        source = source,
        binary = binary,
        actionId = "io-mon.test_build." & stem)
      buildActions.add(edge.action)

      let executeEdge = edge.testBinary.run(
        actionId = "io-mon.test_execute." & stem,
        requiredBinaries = @[cliOutput],
        extraInputs = @[shimOutput],
        registerImplicitName = false)
      executeActions.add(executeEdge)

    # Portable tests — always in the graph.
    let portableTestSpecs = @[
      TestSpec(source: "tests/portable/test_io_mon_builds_standalone.nim", binary: "build/test-bin/test_io_mon_builds_standalone" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_snoop_cli_smoke.nim", binary: "build/test-bin/test_io_mon_snoop_cli_smoke" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_capabilities.nim", binary: "build/test-bin/test_io_mon_capabilities" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_endpoint_security.nim", binary: "build/test-bin/test_io_mon_endpoint_security" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_rd_classification.nim", binary: "build/test-bin/test_io_mon_rd_classification" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_parity_with_fs_snoop.nim", binary: "build/test-bin/test_io_mon_parity_with_fs_snoop" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_sig_safe_committed_frame.nim", binary: "build/test-bin/test_io_mon_sig_safe_committed_frame" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_s1_external_content.nim", binary: "build/test-bin/test_io_mon_s1_external_content" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_post_fork_sentinel_hygiene.nim", binary: "build/test-bin/test_io_mon_post_fork_sentinel_hygiene" & binSuffix),
      TestSpec(source: "tests/portable/test_io_mon_t0_completeness.nim", binary: "build/test-bin/test_io_mon_t0_completeness" & binSuffix),
    ]

    for spec in portableTestSpecs:
      emitTestPair(spec.source, spec.binary, testBuildActions, testExecuteActions)

    # POSIX tests — only compilable/runnable on POSIX platforms.
    when defined(posix):
      let posixTestSpecs = @[
        TestSpec(source: "tests/posix/test_io_mon_shim_builds_standalone.nim", binary: "build/test-bin/test_io_mon_shim_builds_standalone" & binSuffix),
        TestSpec(source: "tests/posix/test_io_mon_snoop_cli_capture.nim", binary: "build/test-bin/test_io_mon_snoop_cli_capture" & binSuffix),
      ]
      for spec in posixTestSpecs:
        emitTestPair(spec.source, spec.binary, testBuildActions, testExecuteActions)

    # macOS tests — macOS only.
    when defined(macosx):
      let macosTestSpecs = @[
        TestSpec(source: "tests/macos/test_io_mon_macos_s2_fd_fidelity.nim", binary: "build/test-bin/test_io_mon_macos_s2_fd_fidelity" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_mmap_reentrancy.nim", binary: "build/test-bin/test_io_mon_macos_mmap_reentrancy" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r5_path_canon.nim", binary: "build/test-bin/test_io_mon_macos_r5_path_canon" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r5_mmap_fd.nim", binary: "build/test-bin/test_io_mon_macos_r5_mmap_fd" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_bodypatch_open_mode.nim", binary: "build/test-bin/test_io_mon_macos_bodypatch_open_mode" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_threaded_write.nim", binary: "build/test-bin/test_io_mon_macos_threaded_write" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r5_raw_syscall.nim", binary: "build/test-bin/test_io_mon_macos_r5_raw_syscall" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_xpc_mach_breakaway.nim", binary: "build/test-bin/test_io_mon_macos_xpc_mach_breakaway" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_symlink.nim", binary: "build/test-bin/test_io_mon_macos_symlink" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r4_write.nim", binary: "build/test-bin/test_io_mon_macos_r4_write" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_record_once.nim", binary: "build/test-bin/test_io_mon_macos_record_once" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_bodypatch_resolution.nim", binary: "build/test-bin/test_io_mon_macos_bodypatch_resolution" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r4_residual.nim", binary: "build/test-bin/test_io_mon_macos_r4_residual" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_content_hooks.nim", binary: "build/test-bin/test_io_mon_macos_content_hooks" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r4_s3b_linktime.nim", binary: "build/test-bin/test_io_mon_macos_r4_s3b_linktime" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_setexec.nim", binary: "build/test-bin/test_io_mon_macos_setexec" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r4_v1_vfork_exit.nim", binary: "build/test-bin/test_io_mon_macos_r4_v1_vfork_exit" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r4_dir.nim", binary: "build/test-bin/test_io_mon_macos_r4_dir" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_ipc_breakaway.nim", binary: "build/test-bin/test_io_mon_macos_ipc_breakaway" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_s3_residuals.nim", binary: "build/test-bin/test_io_mon_macos_s3_residuals" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r5_determinism.nim", binary: "build/test-bin/test_io_mon_macos_r5_determinism" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_sip_system_child.nim", binary: "build/test-bin/test_io_mon_macos_sip_system_child" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_bodypatch.nim", binary: "build/test-bin/test_io_mon_macos_bodypatch" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_round2_rb.nim", binary: "build/test-bin/test_io_mon_macos_round2_rb" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_s1_channels.nim", binary: "build/test-bin/test_io_mon_macos_s1_channels" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_readdir_inode64.nim", binary: "build/test-bin/test_io_mon_macos_readdir_inode64" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_rd.nim", binary: "build/test-bin/test_io_mon_macos_rd" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_bodypatch_spawn.nim", binary: "build/test-bin/test_io_mon_macos_bodypatch_spawn" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_library_load.nim", binary: "build/test-bin/test_io_mon_macos_library_load" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_rename.nim", binary: "build/test-bin/test_io_mon_macos_rename" & binSuffix),
        TestSpec(source: "tests/macos/test_io_mon_macos_r5_kill_sentinel.nim", binary: "build/test-bin/test_io_mon_macos_r5_kill_sentinel" & binSuffix),
      ]
      for spec in macosTestSpecs:
        emitTestPair(spec.source, spec.binary, testBuildActions, testExecuteActions)

    # Linux tests — Linux only.
    when defined(linux):
      let linuxTestSpecs = @[
        TestSpec(source: "tests/linux/test_io_mon_inline_patch_predicate.nim", binary: "build/test-bin/test_io_mon_inline_patch_predicate" & binSuffix),
        TestSpec(source: "tests/linux/test_io_mon_linux_stdio_ipc.nim", binary: "build/test-bin/test_io_mon_linux_stdio_ipc" & binSuffix),
        TestSpec(source: "tests/linux/test_io_mon_linux_inline_asm_exit_group.nim", binary: "build/test-bin/test_io_mon_linux_inline_asm_exit_group" & binSuffix),
      ]
      for spec in linuxTestSpecs:
        emitTestPair(spec.source, spec.binary, testBuildActions, testExecuteActions)

    # Windows tests — Windows only.
    when defined(windows):
      let windowsTestSpecs = @[
        TestSpec(source: "tests/windows/test_io_mon_windows_flush_parity.nim", binary: "build/test-bin/test_io_mon_windows_flush_parity" & binSuffix),
      ]
      for spec in windowsTestSpecs:
        emitTestPair(spec.source, spec.binary, testBuildActions, testExecuteActions)

    discard collect("test", testExecuteActions)
    discard collect("test-builds", testBuildActions)
