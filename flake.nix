{
  description = "Filesystem and process monitoring library and tools";

  inputs = {
    nixos-modules.url = "github:metacraft-labs/devops-modules";
    nixpkgs.follows = "nixos-modules/nixpkgs-unstable";
    flake-parts.follows = "nixos-modules/flake-parts";
    git-hooks.follows = "nixos-modules/git-hooks-nix";
    stackable-hooks-src = {
      # Pinned to the dev revision the Windows shim compiles against
      # (injectShimIntoChildReport / ioChildTerminated, the fix that never
      # resumes a child mid-injection). It used to float on the default
      # branch (`main`), which lags dev, and the lock sat on c6cf6ad.
      url = "github:metacraft-labs/nim-stackable-hooks/72f578249e9d8bbca8e3705c8a41ed5085c05bf9";
      flake = false;
    };
    shm-queue-src = {
      url = "github:metacraft-labs/nim-shm-queue/02f442ac12ce2587d9c053c527041097af38609f";
      flake = false;
    };
    shm-gset-src = {
      url = "github:metacraft-labs/nim-shm-gset/43a61120ae54b542c3e3038453094cca707a6c05";
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
        { pkgs, config, ... }:
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

          packages.default = pkgs.stdenv.mkDerivation {
            pname = "io-mon";
            inherit version;
            src = ./.;

            nativeBuildInputs = [
              pkgs.just
              pkgs.nim2
            ];

            STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src";
            SHM_QUEUE_SRC = "${inputs.shm-queue-src}/src";
            SHM_GSET_SRC = "${inputs.shm-gset-src}/src";

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

          devShells.default = pkgs.mkShell {
            RELEASE_STACKABLE_HOOKS_SRC = "${inputs.stackable-hooks-src}/src";
            RELEASE_SHM_QUEUE_SRC = "${inputs.shm-queue-src}/src";
            RELEASE_SHM_GSET_SRC = "${inputs.shm-gset-src}/src";
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
