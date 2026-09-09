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
3. **The secret leaks are fixed**, in v0.1.1 and v0.1.3. A release that prints a credential on a malformed file should not be one people install; see [known-issues.md](known-issues.md).
4. **`flake.nix` is in the repo.** After changing it, run `nix build` and commit the regenerated `flake.lock`.
5. **PyPI is wired but switched off.** `pyproject.toml` carries the `credmap-cli` name and metadata, and `release.yml` has the publish job, but the job is skipped unless the repository variable `PUBLISH_TO_PYPI` is `true`. Turning it on takes three steps, the first two of which cannot be done from a workflow:

   ```
   1. pypi.org → account settings → Publishing → add a pending publisher:
      project credmap-cli, owner c-wenlong, repo credmap,
      workflow release.yml, environment pypi
   2. GitHub repo settings → Environments → new environment named "pypi"
   3. gh variable set PUBLISH_TO_PYPI --body true
   ```

   The repository must be public for this to be worth doing: publishing an sdist publishes the source.

## Cutting a release

The version lives in two places today: `pyproject.toml` and
`src/credmap/__init__.py`. Nothing enforces that they agree except the CI
guard below, so bump both.

```bash
# bump version in pyproject.toml and src/credmap/__init__.py,
# add a section to CHANGELOG.md, then
uv lock                      # keeps uv.lock in step, or CI's --frozen sync fails
git commit -am "Release 0.1.4"
git tag -a v0.1.4 -m "credmap 0.1.4"
git push origin main
git push origin v0.1.4
```

What fires:

- **Nix**: nothing. The tag exists to be pinned. Consumers edit their input and run `nix flake update credmap`.
- **GitHub Actions**: `release.yml` runs the suite, checks the tag against both version literals, builds with `uv build`, and creates a GitHub release with the sdist and wheel attached. It also publishes to PyPI with Trusted Publishing and PEP 740 attestations, when `PUBLISH_TO_PYPI` is set. `ci.yml` runs the suite on every push and pull request on Linux and macOS, Python 3.11 and 3.13.

Then on the author's machine: make the dotfiles edits in
[install.md](install.md#with-nix-recommended-for-nix-darwin-and-home-manager-users),
run the rebuild, and `uv tool uninstall credmap`.

## `flake.nix`

The file is [`flake.nix`](../flake.nix) in the repository root; read it there
rather than from a copy here, which would drift. It builds with
`buildPythonApplication` against the same nixpkgs branch the author's machine
pins, reads its version out of `pyproject.toml` so the tag and the derivation
cannot disagree, and runs the suite under `pytestCheckHook`.

Notes worth keeping:

- `pyproject = true` with `build-system` and `dependencies` is the current form; `format = "pyproject"` with `propagatedBuildInputs` is deprecated.
- The `src` fileset lists only `pyproject.toml`, `README.md`, `src` and `tests`, so editing AGENTS.md or `uv.lock` does not trigger a rebuild.
- Untracked files are silently dropped from a flake build. A new module you forgot to `git add` produces a confusing failure or a silently incomplete build.
- The flake never reads `uv.lock`. uv stays the local dev tool; Nix resolves PyYAML from nixpkgs. uv2nix would add three inputs to solve a lockfile-fidelity problem a one-dependency project does not have.
- Do not switch to `hatch-vcs`. A source tarball has no `.git` for the tag to be read from, and the derivation reads the version out of `pyproject.toml`.

## PyPI metadata

In [`pyproject.toml`](../pyproject.toml). The distribution is `credmap-cli`
while the import package and the console script stay `credmap`; the
`[tool.hatch.build.targets.wheel] packages` line is what allows that, by
overriding hatchling's name-based inference of the source directory.

Do not add a `License :: OSI Approved` classifier alongside `license = "MIT"`;
build tools may reject having both. Hatchling validates classifiers against the
live trove list, so a typo fails the build.

## Workflows

[`ci.yml`](../.github/workflows/ci.yml) and
[`release.yml`](../.github/workflows/release.yml).

Two things in them were learned the hard way. Pin actions to tags that exist:
the first release failed because `astral-sh/setup-uv@v9` was invented, and
there is no `v9` major tag. And attestations are on by default in
`gh-action-pypi-publish` from v1.11.0, needing only `id-token: write`.

A release created with `GITHUB_TOKEN` does not trigger downstream
`on: release` workflows, which is why nothing else keys off it.

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
