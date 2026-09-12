{
  description = "Read-only discovery for credential stores scattered across your machine";

  # Matches the consumer's dotfiles pin, so `follows` dedupes rather than
  # silently swapping Python 3.14 (unstable) for 3.13 (26.05).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAllSystems (pkgs: rec {
        default = credmap;

        credmap = pkgs.python3Packages.buildPythonApplication {
          pname = "credmap";
          # Single source of truth: the tag, the wheel and the derivation
          # cannot drift apart.
          version = (lib.importTOML ./pyproject.toml).project.version;
          pyproject = true;

          # Only these paths affect the build hash. Editing AGENTS.md or
          # uv.lock does not trigger a rebuild.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./pyproject.toml
              ./README.md   # pyproject declares readme = "README.md"
              ./src
              ./tests
            ];
          };

          build-system = with pkgs.python3Packages; [ hatchling ];
          dependencies = with pkgs.python3Packages; [ pyyaml ];
          # coreutils: the liveness tests write stub CLIs that call sleep,
          # yes, head, cat and touch. stdenv supplies them, but the tests
          # depend on them, so declare it.
          nativeCheckInputs = [ pkgs.coreutils ]
            ++ (with pkgs.python3Packages; [ pytestCheckHook ]);
          pythonImportsCheck = [ "credmap" ];

          meta = {
            description = "Read-only discovery for credential stores scattered across your machine";
            homepage = "https://github.com/c-wenlong/credmap";
            license = lib.licenses.mit;
            mainProgram = "credmap";
            platforms = lib.platforms.unix;
          };
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [ ps.pyyaml ps.pytest ]))
            pkgs.uv
          ];
        };
      });
    };
}
