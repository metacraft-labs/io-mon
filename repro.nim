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

import std/[algorithm, os, strutils]

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
# NOTE: ``repro_dsl_stdlib/packages/nim`` is deliberately NOT imported here.
# The ``package`` macro's ``usesImportCode`` pass auto-imports it ``as
# nim_module`` because ``"nim >=2.0"`` appears in the ``uses:`` block below,
# which is what makes the bare ``nim`` identifier in ``nim.c(...)`` resolve to
# the tool const. A direct ``import repro_dsl_stdlib/packages/nim`` shadows that
# const with the module name and breaks the package declaration (the package
# name fails to resolve — ``undeclared identifier``). See the same note in
# reprobuild's own ``repro.nim``.
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

    # Sibling Nim-library producers (SC-11 develop-mode from-source
    # consumption — the same shape ``nim-agents`` uses for its
    # ``nim-acp`` / ``nim-agent-harbor`` siblings). ``src`` imports
    # ``stackable_hooks/*`` (the interpose framework) and
    # ``src/io_mon/shm/dep_queue`` imports ``shm_queue/ring`` (the MPSC ring).
    # Naming the two workspace repos here makes reprobuild build each from
    # source (their ``library stackable_hooks`` / ``library shm_queue``) and
    # thread their ``src/`` roots onto this repo's ``nim c --path:`` via the
    # ``nimPathDirs`` aux channel — replacing ``config.nims``'s hardcoded
    # ``--path:../nim-stackable-hooks/src`` + ``$SHM_QUEUE_SRC`` for the
    # engine-driven compile (``config.nims`` is not read by the engine's build
    # edges, only by a plain ``nimble``/``nim c`` invocation). The scripted
    # shim edge still resolves ``$STACKABLE_HOOKS_SRC`` itself.
    "nim-stackable-hooks"
    "nim-shm-queue"

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
      # ``src`` reproduces ``config.nims``'s ``switch("path", "src")`` for the
      # engine compile (which does not read ``config.nims``). The sibling
      # ``stackable_hooks`` / ``shm_queue`` ``src`` roots ride in automatically
      # via the ``uses:`` ``nimPathDirs`` channel.
      paths = @["src"],
      extraInputs = @["src", "io_mon.nimble"],
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
        # ``src`` + ``tests/helpers`` reproduce ``config.nims``'s path
        # switches for the engine compile; the sibling ``stackable_hooks`` /
        # ``shm_queue`` ``src`` roots ride in via the ``uses:`` ``nimPathDirs``
        # channel.
        paths = @["src", "tests/helpers"],
        extraInputs = @["src", "tests/helpers", "io_mon.nimble"],
        actionId = "io-mon.test_build." & stem)
      buildActions.add(edge.action)

      let executeEdge = edge.testBinary.run(
        actionId = "io-mon.test_execute." & stem,
        requiredBinaries = @[cliOutput],
        extraInputs = @[shimOutput],
        registerImplicitName = false)
      executeActions.add(executeEdge)

    # Portable tests — always in the graph.
    proc testSpecsUnder(dir: string): seq[TestSpec] =
      ## Keep the Reprobuild graph in lockstep with Nimble's directory-based
      ## discovery. Sorting removes filesystem enumeration order from the graph.
      if not dirExists(dir):
        return
      for kind, path in walkDir(dir):
        if kind notin {pcFile, pcLinkToFile}:
          continue
        let name = path.extractFilename
        if not name.startsWith("test_") or not name.endsWith(".nim"):
          continue
        let stem = name[0 ..< name.len - ".nim".len]
        result.add TestSpec(
          source: path.replace('\\', '/'),
          binary: "build/test-bin/" & stem & binSuffix)
      result.sort(proc(a, b: TestSpec): int = cmp(a.source, b.source))

    var selectedTestDirs = @["tests/portable"]

    # POSIX tests — only compilable/runnable on POSIX platforms.
    when defined(posix):
      selectedTestDirs.add("tests/posix")

    # macOS tests — macOS only.
    when defined(macosx):
      selectedTestDirs.add("tests/macos")

    # Linux tests — Linux only.
    when defined(linux):
      selectedTestDirs.add("tests/linux")

    # Windows tests — Windows only.
    when defined(windows):
      selectedTestDirs.add("tests/windows")

    for dir in selectedTestDirs:
      for spec in testSpecsUnder(dir):
        emitTestPair(spec.source, spec.binary, testBuildActions, testExecuteActions)

    discard collect("test", testExecuteActions)
    discard collect("test-builds", testBuildActions)
