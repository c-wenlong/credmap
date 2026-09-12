# Installing

credmap is pure Python 3.11+ with one dependency, PyYAML. It runs on macOS and
Linux. The binary name is `credmap` whichever route you use.

## From a checkout

```bash
git clone https://github.com/c-wenlong/credmap
uv tool install ./credmap
```

That puts `credmap` at `~/.local/bin/credmap`. The install is a copy, not a
link, so re-run with `--force` after changing the source. For a live-editing
install, run `uv tool install -e .` inside the checkout.

Upgrading a git-installed tool is also a `--force` reinstall at the new tag.
`uv tool upgrade` resolves the name against PyPI rather than the original git
URL, so it does not track a checkout. This is why the declarative routes below
exist.

## With Nix (recommended for nix-darwin and home-manager users)

The repository ships a `flake.nix`. Add it as an input pinned to a release
tag and put the package in your list. `nix run github:c-wenlong/credmap`
also works for a one-off. Both edits are shown against a nix-darwin plus home-manager flake.

In your `flake.nix` inputs:

```nix
credmap = {
  url = "github:c-wenlong/credmap/v0.1.4";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

Use the `github:owner/repo/<tag>` form. A `git+ssh` URL with `?ref=v0.1.0`
expands to a branch name and fails on a tag, and under `sudo darwin-rebuild`
the fetch runs as root against root's SSH config.

Thread `inputs` through to your modules if you do not already. In the
nix-darwin call:

```nix
specialArgs = { inherit user inputs; };
home-manager.extraSpecialArgs = { inherit user inputs; };
```

and accept it at the top of `home.nix`:

```nix
{ config, lib, pkgs, user, inputs, ... }:
```

Then add the package. Append outside the `with pkgs;` list so `pkgs` cannot
shadow `inputs`:

```nix
home.packages = with pkgs; [
  # ... existing packages
] ++ [
  inputs.credmap.packages.${pkgs.stdenv.hostPlatform.system}.default
];
```

Upgrade by editing the tag, then:

```bash
nix flake update credmap
sudo darwin-rebuild switch --flake ~/.dotfiles#mac
```

Rollback is free through darwin generations.

### While the repository is private

A `github:` fetch of a private repo needs a token that the evaluator can
read. With `sudo darwin-rebuild`, that is root's client config, not yours:

```bash
sudo install -d -m 700 /var/root/.config/nix
printf 'access-tokens = github.com=%s\n' "$(gh auth token)" \
  | sudo tee /var/root/.config/nix/nix.conf >/dev/null
sudo chmod 600 /var/root/.config/nix/nix.conf

install -d -m 700 ~/.config/nix
printf 'access-tokens = github.com=%s\n' "$(gh auth token)" > ~/.config/nix/nix.conf
chmod 600 ~/.config/nix/nix.conf
```

Keep the token out of your nix config: anything in `nix.settings` or
`determinateNix.customSettings` lands in a world-readable store path. The
`gh auth token` value rotates when gh re-authenticates; a fine-grained PAT
scoped to read-only contents on this one repo is more stable for unattended
rebuilds. All of this goes away if the repo is public.

### After switching

Remove the old copy so two binaries are not on PATH:

```bash
uv tool uninstall credmap
```

## From PyPI

Nothing is published yet. The distribution name is reserved as `credmap-cli`
because `credmap` on PyPI is held by an unrelated 2022 upload, and the
command stays `credmap` either way. The release workflow carries the publish
job but skips it unless the repository variable `PUBLISH_TO_PYPI` is `true`,
which also needs a registered Trusted Publisher and a `pypi` environment;
see [releasing.md](releasing.md). Once it is switched on:

```bash
uv tool install credmap-cli
# or
pipx install credmap-cli
```

## Homebrew

Not provided. A tap needs a second repository, hand-maintained dependency
checksums, a formula-bump workflow, and an explicit trust entry now that
Homebrew 6 refuses untrusted third-party taps. On nix-darwin with
`onActivation.cleanup = "zap"`, the trust store is also reset on every
rebuild, so trust must be declared in the tap entry itself. And Homebrew has
removed its private-repository download strategies, so a private source repo
cannot be fetched at all. The formula skeleton is kept in
[releasing.md](releasing.md#homebrew-if-ever-needed) in case that changes.

## Verifying

```bash
credmap --version
credmap paths --json | head
```
