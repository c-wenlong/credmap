# Releasing

Decision, recorded 2026-09-09: **ship a `flake.nix` in the repo as the install
path for the author's machine, publish to PyPI as `credmap-cli` if and when
the repo goes public, and do not run a Homebrew tap.** The reasoning is in
[install.md](install.md#homebrew) and in the comparison below.

| | Nix flake | PyPI + `uv tool` | Homebrew tap |
|---|---|---|---|
| Works with a private repo | yes, with an access token | no, publishing exposes the source | no, private download strategies were removed |
| Second repository needed | no | no | yes, `homebrew-tap` |
| Release pipeline | none, a tag is enough | one workflow | PyPI first, then a bump job in the tap |
| Config lines on nix-darwin | one input, one package line | none, lives outside nix | tap entry with `trusted = true`, brew entry |
| Upgrade | edit the tag, rebuild | `uv tool upgrade` | tap bump, then rebuild |
| Rollback | free via generations | none | awkward |
| Non-nix users | only nix users | everyone | brew users |
| Interaction with `cleanup = "zap"` | none | none | trust store reset every rebuild |

## Before the first release

1. **`LICENSE` is MIT**, added 2026-09-09. `license-files`, the flake's `meta.license` and any nixpkgs submission depend on it.
2. **Decide visibility.** Public unlocks PyPI and removes the access-token bootstrap. Private is fine and flake-only.
3. **Fix the secret leaks in [known-issues.md](known-issues.md#secret-leaks).** A release that prints a credential on a malformed file should not be the first one people install.
4. **`flake.nix` is in the repo** (reproduced below). After changing it, run `nix build` and commit the regenerated `flake.lock`.
5. **PyPI is wired but not registered.** `pyproject.toml` already carries the `credmap-cli` name and metadata, and `.github/workflows/release.yml` publishes on tag. Two manual steps remain and neither can be done from a workflow: register a pending Trusted Publisher on PyPI (project `credmap-cli`, owner `c-wenlong`, repo `credmap`, workflow `release.yml`, environment `pypi`) and create the `pypi` environment in the GitHub repo settings. Until then the `publish` job fails and the GitHub release still succeeds.

## Cutting a release

The version lives in two places today: `pyproject.toml` and
`src/credmap/__init__.py`. Nothing enforces that they agree except the CI
guard below, so bump both.

```bash
# bump version in pyproject.toml and src/credmap/__init__.py, then
git commit -am "Release v0.1.1"
git tag v0.1.1
git push && git push --tags
```

What fires:

- **Nix**: nothing. The tag exists to be pinned. Consumers edit their input and run `nix flake update credmap`.
- **GitHub Actions**: `release.yml` runs the suite, checks the tag against both version literals, builds with `uv build`, creates a GitHub release with the sdist and wheel attached, and publishes to PyPI with Trusted Publishing and PEP 740 attestations. `ci.yml` runs the suite on every push and pull request on Linux and macOS, Python 3.11 and 3.13.

Then on the author's machine: make the dotfiles edits in
[install.md](install.md#with-nix-recommended-for-nix-darwin-and-home-manager-users),
run the rebuild, and `uv tool uninstall credmap`.

## `flake.nix`

Verified by building on `aarch64-darwin`: `nix build` succeeded, the import
check passed, and all 74 tests ran under `pytestCheckHook`.

```nix
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
          nativeCheckInputs = with pkgs.python3Packages; [ pytestCheckHook ];
          pythonImportsCheck = [ "credmap" ];

          meta = {
            description = "Read-only discovery for credential stores scattered across your machine";
            homepage = "https://github.com/c-wenlong/credmap";
            license = lib.licenses.mit;   # add a LICENSE file to make this true
            mainProgram = "credmap";
            platforms = lib.platforms.unix;
          };
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
```

Notes:

- `pyproject = true` with `build-system` and `dependencies` is the current form; `format = "pyproject"` with `propagatedBuildInputs` is deprecated.
- Untracked files are silently dropped from a flake build. A new module you forgot to `git add` produces a confusing failure or a silently incomplete build.
- The flake never reads `uv.lock`. uv stays the local dev tool; Nix resolves PyYAML from nixpkgs. uv2nix would add three inputs to solve a lockfile-fidelity problem a one-dependency project does not have.
- Do not switch to `hatch-vcs`. A source tarball has no `.git` for the tag to be read from, and the derivation reads the version out of `pyproject.toml`.

## PyPI metadata

Already in `pyproject.toml`; reproduced for reference.

```toml
[build-system]
requires = ["hatchling>=1.27"]
build-backend = "hatchling.build"

[project]
name = "credmap-cli"
version = "0.1.0"
description = "Read-only discovery for credential stores scattered across your machine"
readme = "README.md"
requires-python = ">=3.11"
license = "MIT"
license-files = ["LICENSE"]
authors = [{ name = "Kai Chen" }]
keywords = ["credentials", "secrets", "cli", "discovery"]
classifiers = [
  "Development Status :: 3 - Alpha",
  "Environment :: Console",
  "Intended Audience :: Developers",
  "Operating System :: OS Independent",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Topic :: Security",
  "Topic :: Utilities",
]
dependencies = ["PyYAML>=6.0"]

[project.scripts]
credmap = "credmap.cli:main"

[project.urls]
Homepage = "https://github.com/c-wenlong/credmap"
Issues = "https://github.com/c-wenlong/credmap/issues"
Changelog = "https://github.com/c-wenlong/credmap/releases"

[tool.hatch.build.targets.wheel]
packages = ["src/credmap"]
```

The existing `packages = ["src/credmap"]` line is what lets the distribution
name differ from the import name. Do not add a `License :: OSI Approved`
classifier alongside `license = "MIT"`; build tools may reject both.

Trusted Publishing for a project that does not exist yet goes through a
pending publisher: PyPI account settings, Publishing, add a pending publisher
with project `credmap-cli`, owner `c-wenlong`, repository `credmap`, workflow
`release.yml`, environment `pypi`. The name is not reserved until the first
successful publish.

## `.github/workflows/release.yml`

Already in the repo; reproduced for reference.

```yaml
name: Release

on:
  push:
    tags: ["v[0-9]+.[0-9]+.[0-9]+"]

permissions: {}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@v9
      # Guards the three places the version lives: the tag, pyproject.toml,
      # and src/credmap/__init__.py.
      - name: Version matches tag
        run: |
          test "v$(uv version --short)" = "$GITHUB_REF_NAME"
          grep -q "__version__ = \"$(uv version --short)\"" src/credmap/__init__.py
      - run: uv build --no-sources
      - uses: actions/upload-artifact@v7
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/credmap-cli
    permissions:
      id-token: write   # Trusted Publishing and PEP 740 attestations
    steps:
      - uses: actions/download-artifact@v8
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@v1.14.2

  github-release:
    needs: publish
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v8
        with:
          name: dist
          path: dist/
      - env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: >-
          gh release create "$GITHUB_REF_NAME"
          --repo "$GITHUB_REPOSITORY" --generate-notes dist/*
```

Attestations are on by default in the publish action from v1.11.0. A release
created with `GITHUB_TOKEN` does not trigger downstream `on: release`
workflows.

## Homebrew, if ever needed

Kept on record. Requires a public repo and a PyPI release, since the formula
should point at the immutable PyPI sdist rather than a GitHub tarball: brew
livecheck detects PyPI URLs with no configuration and `brew bump-formula-pr
--version=` rewrites the hashed URL natively.

Tap repo `c-wenlong/homebrew-tap`, formula at `Formula/credmap.rb`, scaffolded
by `brew tap-new c-wenlong/homebrew-tap`, which also generates an
`autobump.yml` that runs `brew bump --no-fork --open-pr` with the default
token. The popular `mislav/bump-homebrew-formula-action` cannot bump formulae
with PyPI `resource` blocks, by its own README.

```ruby
class Credmap < Formula
  include Language::Python::Virtualenv

  desc "Read-only discovery for credential stores scattered across your machine"
  homepage "https://github.com/c-wenlong/credmap"
  url "https://files.pythonhosted.org/packages/XX/XX/XXXX/credmap_cli-0.1.0.tar.gz"  # fill in after first upload
  sha256 "FILL IN"
  license "MIT"
  head "https://github.com/c-wenlong/credmap.git", branch: "main"

  depends_on "python@3.14"

  pypi_packages package_name: "credmap-cli"

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz"
    sha256 "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/credmap --version")
    require "json"
    JSON.parse(shell_output("#{bin}/credmap paths --json"))
  end
end
```

On nix-darwin the tap entry must carry trust, and a fully qualified brew name
keeps the tap alive through `cleanup = "zap"`:

```nix
taps = [ { name = "c-wenlong/tap"; trusted = true; } ];
brews = [ "c-wenlong/tap/credmap" ];
```

## Nixpkgs proper

Not worth it now. It needs a license, two to four hours of work, weeks to
months of review, and an open-ended maintenance commitment with Zero Hydra
Failures pings every six months. The in-repo flake gives the same install
today. Revisit if the tool picks up outside users.
