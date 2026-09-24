{
  description = "Obscura — private SSH file sharing with encrypted PNG carriers";

  inputs = {
    # Go 1.26 lives in unstable; obscura's go.mod requires go >= 1.26.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Bump this when go.mod's minimum changes. The dev shell only needs a
        # toolchain >= 1.26; buildGoModule below reuses the same pkgs.go.
        goToolchain = pkgs.go;

        # obscura package set (client `obscura` + server `obscurad`).
        #
        # vendorHash: buildGoModule fetches modules in a fixed-output derivation
        # and needs the dependency hash. It cannot be computed on a machine
        # without network+nix ahead of time, so it is left as a placeholder.
        # On relic-1, run `nix build` once; Nix will fail and print the correct
        # `got: sha256-...` value — paste it here and rebuild. Alternatively run
        # `go mod vendor` in the source tree and set `vendorHash = null;`.
        obscura = pkgs.buildGoModule {
          pname = "obscura";
          version = "0.1.0";
          src = self;

          vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
          # vendorHash = null; # use this instead if you `go mod vendor` the tree

          # Build both commands; skip the helper tool.
          subPackages = [
            "cmd/obscura"
            "cmd/obscurad"
          ];

          ldflags = [
            "-s"
            "-w"
          ];

          # obscurad is cgo-free (modernc.org/sqlite is pure Go).
          env.CGO_ENABLED = "0";

          meta = with pkgs.lib; {
            description = "Private SSH file sharing with client-side encryption and PNG carriers";
            homepage = "https://github.com/kottesh/obscura";
            license = licenses.mit;
            mainProgram = "obscura";
            platforms = platforms.unix;
          };
        };
      in
      {
        # Development environment: `nix develop`
        devShells.default = pkgs.mkShell {
          name = "obscura-dev";

          packages = [
            goToolchain
            pkgs.gopls
            pkgs.go-tools # staticcheck
            pkgs.gotools # goimports
            pkgs.delve # debugger
            pkgs.just # task runner used by the repo justfile
            pkgs.git
          ];

          # Keep GOPATH/caches inside the project to avoid polluting $HOME on a
          # shared machine; harmless if you prefer the defaults.
          shellHook = ''
            export CGO_ENABLED=0
            echo "obscura dev shell — go $(go version | awk '{print $3}')"
            echo "  build:  just build   (or: go build ./cmd/obscura ./cmd/obscurad)"
            echo "  test:   just test    (go test -race ./...)"
          '';
        };

        # Packages: `nix build .#obscura`  /  `nix build .#obscurad`
        # (both come from the same derivation).
        packages = {
          default = obscura;
          obscura = obscura;
          obscurad = obscura;
        };

        # Runnable apps: `nix run .#obscura -- <args>`
        apps = {
          obscura = {
            type = "app";
            program = "${obscura}/bin/obscura";
          };
          obscurad = {
            type = "app";
            program = "${obscura}/bin/obscurad";
          };
          default = self.apps.${system}.obscura;
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
