{
  description = "Filesystem and process monitoring library and tools";

  inputs = {
    # Keep the shipped SIP replacements available when a child has an empty PATH.
    stackable-hooks-macos-tools = {
      url = "github:metacraft-labs/stackable-hooks-macos-tools/1ad378d58776ec9b6cc73e1c27b8e53c15676f03";
    };
    nixos-modules.url = "github:metacraft-labs/devops-modules";
    nixpkgs.follows = "nixos-modules/nixpkgs-unstable";
    flake-parts.follows = "nixos-modules/flake-parts";
    git-hooks.follows = "nixos-modules/git-hooks-nix";
    stackable-hooks-src = {
      # Keep release payloads and ordinary CI on the same qualified hook
      # source: captured-output lifetime, initialized injection permits and
      # one preparation per executable page. Match .github/sibling-repos,
      # the ordinary Windows checkout and the committed Repro lock.
      # Bumped 059c549 -> 3af8a4e (2026-10-30, nim-stackable-hooks `agents`):
      # the 32-bit ARM (armhf) raw-syscall substrate this shim's Linux inline
      # trap and syscall(2) owner protocol compile against on `__arm__`.
      # 3af8a4e -> 7533478 (2026-10-30): review fixes of that substrate (ARM
      # body patch writes its target word first; idempotent restore).
      url = "github:metacraft-labs/nim-stackable-hooks/75334780682e70b1adb58bf813d869e7f5df63f5";
      flake = false;
    };
    shm-queue-src = {
      # Bumped a3564c13 -> 84fd76b (2026-10-30, `agents`): a new segment file is
      # preallocated, so a full filesystem is ENOSPC at creation instead of
      # SIGBUS at the first header store.
      url = "github:metacraft-labs/nim-shm-queue/84fd76b174d4868e703ba3d599668ee340e0b6ea";
      flake = false;
    };
    shm-gset-src = {
      # Bumped 43a61120 -> 6333cc9 (2026-10-30, `agents`): shard files are backed
      # with storage at creation (`posix_fallocate`), so a full tmpfs fragment
      # directory makes the dependency set unavailable (and the shim fall back to
      # its file transport) instead of killing the monitor root with SIGBUS --
      # the ~1-in-5 cold `repro infra plan` failure measured on rpi2.
      url = "github:metacraft-labs/nim-shm-gset/6333cc915689559b00f81371734783c2e894ca45";
      flake = false;
    };
  };

  outputs =
    inputs@{ flake-parts, nixos-modules, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        nixos-modules.modules.flake.git-hooks
      ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        {
          pkgs,
          config,
          system,
          ...
        }:
        let
          version = builtins.replaceStrings [ "\n" "\r" ] [ "" "" ] (builtins.readFile ./version.txt);
          # git-hooks.nix installs `.pre-commit-config.yaml` and git hooks into
          # `git rev-parse --show-toplevel` of the directory the shell is entered
          # from, so `nix develop /path/to/this-repo` run inside another checkout
          # would plant this repository's hooks there. `ownRepoOnly` runs a snippet
          # only when that toplevel is this repository, recognised by a `flake.nix`
          # identical to the one this shell was evaluated from; anything it cannot
          # establish counts as another repository, so it fails safe.
          # tests/test_dev_shell_writes_nothing_elsewhere.sh
          ownRepoOnly = script: ''
            _own_repo_root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || true)"
            if [ -n "$_own_repo_root" ] && [ -f "$_own_repo_root/flake.nix" ] \
              && [ "$(${pkgs.coreutils}/bin/sha256sum "$_own_repo_root/flake.nix" | ${pkgs.coreutils}/bin/cut -d' ' -f1)" \
                = "${builtins.hashFile "sha256" ./flake.nix}" ]; then
            ${script}
            # git-hooks.nix's installer leaves core.hooksPath as the RELATIVE
            # `.git/hooks`, in the config every worktree shares. A linked worktree
            # cannot resolve it (there `.git` is a file), so git silently runs no
            # hooks there. Point it at the common hooks directory instead.
            if [ "$(${pkgs.git}/bin/git config --local --get core.hooksPath 2>/dev/null)" = .git/hooks ]; then
              ${pkgs.git}/bin/git config --local core.hooksPath "$(${pkgs.git}/bin/git rev-parse --path-format=absolute --git-common-dir)/hooks"
            fi
            # The installer moves each Reprobuild hook dispatcher aside to
            # `<hook>.legacy` and puts pre-commit's shim in its slot, so the managed
            # hook (for pre-push, the publication gate) runs only by accident. Put the
            # dispatcher back and chain the shim as `<hook>.repro-local`, which the
            # dispatcher runs: the layout `repro hooks ensure --vcs` produces.
            _hooks="$(${pkgs.git}/bin/git rev-parse --path-format=absolute --git-path hooks 2>/dev/null || true)"
            for _legacy in "$_hooks"/*.legacy; do
              [ -f "$_legacy" ] && grep -q 'reprobuild hook dispatcher' "$_legacy" || continue
              _slot="''${_legacy%.legacy}"
              if [ -f "$_slot" ] && grep -q 'reprobuild hook dispatcher' "$_slot"; then
                rm -f "$_legacy"
              elif [ ! -e "$_slot" ] || grep -Eq '^# File generated by (pre-commit|prek)' "$_slot"; then
                if [ -f "$_slot.repro-local" ] && ! grep -Eq '^# File generated by (pre-commit|prek)' "$_slot.repro-local"; then
                  echo "git-hooks: $_slot.repro-local is your own hook; run 'repro hooks ensure --vcs' to reconcile." >&2
                  continue
                fi
                if [ -e "$_slot" ]; then mv -f "$_slot" "$_slot.repro-local"; fi
                mv -f "$_legacy" "$_slot"
              else
                echo "git-hooks: $_slot is not a pre-commit shim; run 'repro hooks ensure --vcs' to reconcile." >&2
              fi
            done
            unset _hooks _legacy _slot
            fi
            unset _own_repo_root
          '';
          # Nimble 0.20.1 dynamically looks up TLS methods as well as linking
          # OpenSSL. On Darwin its unconstrained lookup finds system LibreSSL,
          # then passes that library's method to OpenSSL 3 and crashes before
          # executing a task. Bind both lookups to the Nix OpenSSL ABI.
          nimble = pkgs.nimble.overrideAttrs (old: {
            nimFlags = (old.nimFlags or [ ]) ++ [ "-d:sslVersion=3" ];
          });
          # On macOS 26 the ASan runtime of nixpkgs' compiler-rt 21.1.8 hangs
          # every instrumented program before main: InitializeShadowMemory ->
          # get_dyld_hdr walks the shared cache with
          # dyld_shared_cache_iterate_text, whose _Block_copy mallocs, and that
          # malloc re-enters AsanInitFromRtl and spins on the init mutex it
          # holds. scripts/run_sanitizer_tests.sh then never runs a test
          # (metacraft-pm issues/2026-10-01-nix-compiler-rt-asan-startup-hangs-on-macos-26.md).
          # Upstream LLVM 2e7d07a33725 ("Adopt _dyld_get_dyld_header", first
          # released in 22.1.3) asks dyld for its header instead; this is that
          # change backported to 21.x, minus its lib/tsan/go/buildgo.sh hunk
          # (the Go race runtime, which this CMake build does not produce).
          # Darwin only: on Linux the dev shell's derivation changes only by
          # the flake.nix hash its git-hook guard embeds.
          #
          # The patched runtime must replace the one the stdenv's wrapper
          # links into its resource-root, which is NOT
          # `pkgs.llvmPackages.compiler-rt` (a different derivation), so it is
          # taken from the wrapper's own arguments. Evaluation fails rather
          # than silently shipping the hang if the wrapper stops having
          # exactly one compiler-rt, if the replacement does not take, or once
          # compiler-rt leaves 21.x: at 22.1.3+ the fix is upstream and this
          # whole override should be deleted.
          # tests/test_dev_shell_asan_program_reaches_main.sh
          darwinSanitizerCc = pkgs.stdenv.cc.override (
            old:
            let
              inherit (pkgs) lib;
              crts = builtins.filter (p: lib.hasPrefix "compiler-rt" (p.pname or "")) old.extraPackages;
              crt =
                if builtins.length crts == 1 then
                  builtins.head crts
                else
                  throw "io-mon flake.nix: expected exactly one compiler-rt in stdenv.cc's extraPackages, found ${toString (builtins.length crts)}; re-derive the ASan startup-hang override";
              patched =
                if lib.versions.major crt.version == "21" then
                  crt.overrideAttrs (a: {
                    patches = (a.patches or [ ]) ++ [ ./nix/patches/compiler-rt-21-darwin-dyld-get-dyld-header.patch ];
                  })
                else
                  throw "io-mon flake.nix: stdenv.cc's compiler-rt is ${crt.version}, not 21.x. 22.1.3+ carries the _dyld_get_dyld_header fix upstream: drop darwinSanitizerCc and its patch; otherwise port the patch.";
              extraBuildCommands = builtins.replaceStrings [ "${crt}" ] [ "${patched}" ] old.extraBuildCommands;
            in
            if
              extraBuildCommands == old.extraBuildCommands
              || lib.hasInfix (builtins.unsafeDiscardStringContext "${crt}") extraBuildCommands
            then
              throw "io-mon flake.nix: stdenv.cc's resource-root no longer links ${crt}; re-derive the ASan startup-hang override"
            else
              {
                inherit extraBuildCommands;
                extraPackages = map (p: if p.outPath == crt.outPath then patched else p) old.extraPackages;
              }
          );
          # The dev shell's `cc`/`clang`, and so the sanitizer arm's, is
          # darwinSanitizerCc on Darwin.
          mkDevShell =
            if pkgs.stdenv.isDarwin then
              pkgs.mkShell.override { stdenv = pkgs.overrideCC pkgs.stdenv darwinSanitizerCc; }
            else
              pkgs.mkShell;
        in
        {
          pre-commit.settings.hooks = {
            shellcheck.enable = true;
            nixfmt.enable = true;
            check-license = {
              enable = true;
              name = "Check License File";
              entry = "bash -c 'if [ ! -f LICENSE ] && [ ! -f LICENSE-APACHE ] && [ ! -f LICENSE-MIT ]; then echo \"Error: No license file (LICENSE, LICENSE-APACHE, LICENSE-MIT) found in repository root!\"; exit 1; fi'";
              files = "^$";
              pass_filenames = false;
            };
          };

          packages = {
            default = pkgs.stdenv.mkDerivation {
              pname = "io-mon";
              inherit version;
              src = ./.;

              nativeBuildInputs = [
                pkgs.just
                pkgs.nim2
              ];

              STACKABLE_HOOKS_BUILT_TOOLS_DIR =
                if pkgs.stdenv.isDarwin then
                  "${inputs.stackable-hooks-macos-tools.packages.${system}.default}"
                else
                  "";
              STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src";
              SHM_QUEUE_SRC = "${inputs.shm-queue-src}/src";
              SHM_GSET_SRC = "${inputs.shm-gset-src}/src";

              postPatch = ''
                patchShebangs scripts/build_shim.sh
              '';

              buildPhase = ''
                runHook preBuild
                just build
                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p "$out/bin" "$out/lib"
                if [ -f build/bin/io-mon ]; then
                  install -m755 build/bin/io-mon "$out/bin/io-mon"
                fi
                for lib in build/lib/*; do
                  [ -e "$lib" ] || continue
                  install -m755 "$lib" "$out/lib/$(basename "$lib")"
                done
                runHook postInstall
              '';
            };
          }
          // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
            # The entry-loss oracle needs a real 32-bit image, also when the
            # engine runs outside the dev shell. A distinct name avoids
            # shadowing the ordinary 64-bit bash used by its controls.
            io-mon-test-i686-sh = pkgs.runCommand "io-mon-test-i686-sh" { } ''
              mkdir -p "$out/bin"
              ln -s ${pkgs.pkgsi686Linux.bash}/bin/bash "$out/bin/io-mon-test-i686-sh"
            '';
          };

          devShells.default = mkDevShell {
            STACKABLE_HOOKS_BUILT_TOOLS_DIR =
              if pkgs.stdenv.isDarwin then
                "${inputs.stackable-hooks-macos-tools.packages.${system}.default}"
              else
                "";
            RELEASE_STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src";
            RELEASE_SHM_QUEUE_SRC = "${inputs.shm-queue-src}/src";
            RELEASE_SHM_GSET_SRC = "${inputs.shm-gset-src}/src";
            # A dynamically linked 32-bit (i686) shell. glibc's loader refuses a
            # 64-bit LD_PRELOAD object in it ("wrong ELF class: ignored") and
            # runs it anyway, so it is the canonical image the shim cannot
            # enter. tests/linux/test_io_mon_uninjectable_image_entry.nim
            # requires it on x86_64-linux (a missing value fails that test
            # there) and skips on every other system, where it is empty.
            IO_MON_TEST_I686_SH =
              if system == "x86_64-linux" then "${pkgs.pkgsi686Linux.bash}/bin/bash" else "";
            # Paired workspace editing keeps using siblings. Release scripts
            # explicitly select the immutable inputs exported above.
            shellHook = ''
              ${ownRepoOnly config.pre-commit.installationScript}
              if [ -z "''${STACKABLE_HOOKS_SRC:-}" ]; then
                if [ -d ../nim-stackable-hooks/src ]; then
                  export STACKABLE_HOOKS_SRC="$(cd ../nim-stackable-hooks/src && pwd)"
                else
                  export STACKABLE_HOOKS_SRC="$RELEASE_STACKABLE_HOOKS_SRC"
                fi
              fi
              if [ -z "''${SHM_QUEUE_SRC:-}" ]; then
                if [ -d ../nim-shm-queue/src ]; then
                  export SHM_QUEUE_SRC="$(cd ../nim-shm-queue/src && pwd)"
                else
                  export SHM_QUEUE_SRC="$RELEASE_SHM_QUEUE_SRC"
                fi
              fi
              if [ -z "''${SHM_GSET_SRC:-}" ]; then
                if [ -d ../nim-shm-gset/src ]; then
                  export SHM_GSET_SRC="$(cd ../nim-shm-gset/src && pwd)"
                else
                  export SHM_GSET_SRC="$RELEASE_SHM_GSET_SRC"
                fi
              fi
            '';
            # Not `inputsFrom = [ config.pre-commit.devShell ]`: that shell's
            # hook installs the git hooks without `ownRepoOnly` (the guarded
            # install is the first line of `shellHook` above). Its packages are
            # appended to `packages` below.
            packages = [
              pkgs.just
              pkgs.nim2
              nimble
              # The macOS directory-transparency regression starts real Python
              # under the production shim; absence must fail, never skip it.
              pkgs.python3
              pkgs.git
              pkgs.nixfmt
              pkgs.nodejs
              # tests/linux/test_io_mon_library_load_closure.nim derives its
              # ground truth from `strace -f -e trace=openat`: the loader
              # closure io-mon claims to observe is compared against the one
              # the kernel actually opened. Without strace in the shell that
              # comparison cannot run, and CI failed with "Could not find
              # command: 'strace'" while it passed on developer machines that
              # happened to have it on PATH.
              # The §4.5(h) REAL-BUILD COMPLETENESS ORACLE
              # (`just test-realbuild-oracle`, tests/realbuild/run_oracle.sh) —
              # the cardinal-sin gate: it drives real cmake+ninja and cargo
              # builds under the shim and checks io-mon's captured input set
              # against the toolchain's OWN dependency data (`ninja -t deps`,
              # cargo/rustc `--emit=dep-info`) and against `strace -f`.
              #
              # These were left to the AMBIENT environment, and the result was a
              # documented `just` target that could not run from ANY shell:
              # measured, `just test-realbuild-oracle` exited 2 with
              # "missing required tool(s) from the ambient environment: cmake
              # cargo rustc" in io-mon's own devShell AND in a bare workspace
              # shell. The script also pulled ninja in with
              # `nix shell nixpkgs#ninja`, a MUTABLE FLAKE-REGISTRY lookup that
              # resolves against whatever nixpkgs the machine last synced.
              #
              # Pinning them is not merely convenience. The oracle's verdict is
              # a comparison against the toolchain's own dep data, so the
              # toolchain is part of the EXPERIMENT: an unpinned cmake/rustc/
              # ninja means the gate measures a different thing on every
              # machine, and a capture gap could appear or vanish with a
              # compiler bump rather than with an io-mon change.
              pkgs.cmake
              pkgs.ninja
              pkgs.cargo
              pkgs.rustc
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              # The sanitizer startup probe exercises both GCC's cc and Clang.
              # Keep GCC ahead of Clang's cc alias on the shell's PATH.
              # Darwin already supplies clang through darwinSanitizerCc.
              pkgs.stdenv.cc
              pkgs.clang
              pkgs.strace
              pkgs.zig
              pkgs.patchelf
              pkgs.binutils
              pkgs.dpkg
              pkgs.rpm
            ]
            ++ config.pre-commit.settings.enabledPackages
            ++ [ config.pre-commit.settings.package ];
          };
        };
    };
}
