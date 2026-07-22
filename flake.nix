{
  description = "bktunnel — pinned-identity, mutual-auth TLS tunnel (Go implementation)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        bktunnel = pkgs.buildGoModule {
          pname = "bktunnel";
          version = "0.1.0";

          src = self;

          # The Go module lives in the go/ subdirectory; the bash
          # implementation sits at the repo root and is not built here.
          modRoot = "go";
          subPackages = [ "cmd/bktunnel" ];

          # The tool uses only the Go standard library — no module
          # dependencies — so there is nothing to vendor.
          vendorHash = null;

          meta = with pkgs.lib; {
            description = "Pinned-identity, mutual-auth TLS tunnel";
            homepage = "https://github.com/zziigguurraatt/bktunnel";
            license = licenses.mit;
            mainProgram = "bktunnel";
          };
        };

        default = bktunnel;
      });

      apps = forAllSystems (pkgs: rec {
        bktunnel = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.bktunnel}/bin/bktunnel";
        };
        default = bktunnel;
      });

      # NixOS module: declarative systemd services — the flake-native equivalent
      # of packaging/systemd/. Import it and declare tunnels under
      # services.bktunnel.instances.<name>. The package defaults to this flake's
      # build (override services.bktunnel.package to change it).
      nixosModules.bktunnel = { pkgs, lib, ... }: {
        imports = [ ./packaging/nixos/module.nix ];
        services.bktunnel.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.bktunnel;
      };
      nixosModules.default = self.nixosModules.bktunnel;
    };
}
