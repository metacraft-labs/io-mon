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
##
## ## Tool provisioning
##
## ``defaultToolProvisioning "path"`` matches reprobuild's own ``repro.nim`` and
## the trace-format-nim / runquota pattern: the io-mon dev shell (``nix
## develop`` / ``.envrc``) on macOS+Linux and ``env.ps1`` on Windows already put
## ``nim`` / ``nimble`` / the C compiler / ``sh`` on ``PATH``, so the weak-local
## path-mode resolver is the right default and ``repro build`` does not insist on
## ``--tool-provisioning=path`` at the CLI.
##
## ## Validation
##
## Parses + type-checks under the DSL with::
##
##   nim check --path:<reprobuild>/libs/repro_project_dsl/src \
##             --path:<reprobuild>/libs/repro_dsl_stdlib/src ... repro.nim

import repro_project_dsl
# ``shell(...)`` — the coarse-grained build-action wrapper around the ``sh``
# typed tool. Pulling in the stdlib ``sh`` package both defines ``shell`` and
# registers the ``sh`` selector the ``uses:`` floor below pins.
import repro_dsl_stdlib/packages/sh

package io_mon:
  defaultToolProvisioning "path"

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
    # Wraps the ``nimble buildSnoop`` task (``nim c --path:../nim-stackable-hooks/src
    # --path:src --threads:on --out:build/bin/io-mon cmd/io_mon_snoop.nim``).
    let cliOutput = "build/bin/io-mon" & binSuffix
    let cliBuild = shell(
      command = "nimble buildSnoop",
      actionId = "io-mon.cli.build_snoop",
      extraInputs = @[
        "io_mon.nimble",
        "config.nims",
        "src",
        "cmd/io_mon_snoop.nim",
      ],
      extraOutputs = @[cliOutput])
    # Enrol the CLI into the conventional ``default`` collection so a bare
    # ``repro build`` / ``repro build io-mon`` materialises it (see
    # ``repro_cli_support.DefaultBuildCollectionName``).
    discard collect("default", @[cliBuild])

    # ---- Test suite (``io-mon:test``) --------------------------------------
    #
    # Wraps the ``nimble test`` task as a single coarse test action. A clean
    # per-``tests/test*.nim`` Mode-A test graph is NOT expressible here because
    # ``test`` is a NimScript ``task`` block (a Mode-B trigger) that also threads
    # the sibling ``--path:../nim-stackable-hooks/src`` and compiles several
    # ``--app:lib`` shim variants internally. Per the Nim convention's Mode-B
    # fallback this is the documented coarse cut: one action that compiles+runs
    # the whole suite. ``cacheable = false`` keeps it from being skipped on a
    # cache hit — a test edge should re-run whenever it is requested. Reachable
    # as ``repro build io-mon:test`` (the repo's dir is ``tests/`` plural, so the
    # ``test`` collection name does not collide with a directory path the way it
    # does in the ruby recorder).
    let testRun = shell(
      command = "nimble test",
      actionId = "io-mon.test.nimble_test",
      cacheable = false,
      extraInputs = @[
        "io_mon.nimble",
        "config.nims",
        "src",
        "tests",
      ])
    discard collect("test", @[testRun])
