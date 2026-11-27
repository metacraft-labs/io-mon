# SPDX-FileCopyrightText: 2026 Metacraft Labs / Schelling Point Labs
# SPDX-License-Identifier: Apache-2.0

{
  description = "io-mon docs — self-contained dev shell for the isonim-docs-powered docs site";

  inputs = {
    # Every input below is locked by the committed `flake.lock` beside this
    # file. Without it each build resolved every input to its branch head, so
    # the site broke whenever an upstream moved (nim-stew, 2026-10-18), with
    # no change in io-mon. Move an input with `nix flake update <input>`.
    #
    # `agents` carries `isonim/content/*`, which isonim-docs `dev` imports and
    # isonim `dev` lacks. Return this to `dev` once isonim promotes `agents`.
    #
    # Fetched with the git fetcher and `submodules=1` on purpose. The isonim
    # tree holds a submodule gitlink (`src/isonim/layout/yoga`), and a
    # `github:` input hashes a tree with an unfetched gitlink differently
    # across Nix versions (2.28 vs current), so a lock written by one version
    # fails with a NAR hash mismatch on the other. Fetching the submodules
    # makes the hash the same in every Nix version.
    isonim.url = "git+https://github.com/metacraft-labs/isonim?ref=agents&submodules=1";

    isonim-docs.url = "github:metacraft-labs/isonim-docs/dev";
    isonim-docs.inputs.isonim.follows = "isonim";

    nim-everywhere = {
      url = "github:metacraft-labs/nim-everywhere/dev";
      flake = false;
    };
    nim-faststreams = {
      url = "github:metacraft-labs/nim-faststreams";
      flake = false;
    };
    nim-stew = {
      # Upstream stew removed `readPragma` in
      # https://github.com/status-im/nim-stew/commit/eeff9f5 ("Drop deprecated
      # APIs"), which isonim's vendored serialization and chronicles still
      # call. The Metacraft fork's `codetracer` branch keeps it.
      url = "github:metacraft-labs/nim-stew/codetracer";
      flake = false;
    };

    codetracer-design-system = {
      url = "github:metacraft-labs/codetracer-design-system";
      flake = false;
    };
  };

  outputs =
    {
      self,
      isonim,
      isonim-docs,
      nim-everywhere,
      nim-faststreams,
      nim-stew,
      codetracer-design-system,
    }:
    let
      inherit (isonim.inputs) flake-utils nixpkgs;
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          inputsFrom = [ isonim.devShells.${system}.default ];
          packages = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.pcre.dev ];

          shellHook = ''
            export IO_MON_DOCS_ISONIM_SRC="${isonim}/src"
            export IO_MON_DOCS_ISONIM_DOCS_SRC="${isonim-docs}/src"
            export IO_MON_DOCS_NIM_EVERYWHERE_SRC="${nim-everywhere}/src"
            export IO_MON_DOCS_NIM_FASTSTREAMS="${nim-faststreams}"
            export IO_MON_DOCS_NIM_STEW="${nim-stew}"
            export IO_MON_DOCS_ISONIM_VENDOR="${isonim}/vendor"
            export IO_MON_DOCS_DESIGN_SYSTEM="${codetracer-design-system}"
            echo "io-mon docs dev shell — framework source from Nix store (isonim-docs + isonim)"
          '';
        };
      }
    );
}
