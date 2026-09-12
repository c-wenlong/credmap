# Security Policy

## Supported versions

credmap is a single-command CLI with no maintenance branch. Only the current
minor gets fixes; upgrading is a rebuild (`nix build`) or `uv tool upgrade`.

| Version | Supported |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

**Do not open a public issue describing a security problem.**

GitHub's [private vulnerability reporting](https://github.com/c-wenlong/credmap/security/advisories/new)
is the preferred channel. It is not enabled on this repository yet, and the
link only works once a maintainer turns it on under Settings → Code security.
Until then, open a public issue saying only that you have found a security
problem and asking for a private channel. Hold the details back until one
exists.

Once you have somewhere private to send it, include:

- What the issue is
- Steps to reproduce, against a synthetic home rather than your real one
  (`tests/conftest.py` builds one)
- What an attacker gets out of it

**Never include a real credential in a report**, in either channel. A masked
value is still a fingerprint.

Reports are acknowledged within 48 hours where possible. This is a personal
project, not a funded one.

## Scope

[docs/security.md](docs/security.md) is the full posture: what has been
verified, what was fixed and when, and what is knowingly open. This section is
the summary of what an attacker or a careless paste can actually reach. Read
that page before reporting, so a documented decision does not arrive as a bug.

In scope:

- **A secret reaching default output.** credmap reads AWS, gcloud, kubeconfig,
  Docker, gh, npm and 20 more: 26 built-in stores in all. Every field it prints goes
  through one `scrub` chokepoint with default-deny masking. A channel that
  prints a value without passing through `scrub` is the highest-severity bug
  this project has, and `tests/test_redact.py` exists to catch it.
- **A write to a credential file.** The package holds no write path: SQLite is
  opened read-only by URI, and output goes to stdout and nowhere else. Anything
  that creates, modifies, locks or leaves a sidecar next to a credential path is
  in scope, including a file created as a side effect of reading one.
- **Command injection or an unbounded probe under `--check`.** Probes are the
  only code that runs a subprocess. They run without a shell, with a per-probe
  timeout and an overall deadline, reading a capped amount of output. A profile
  name is one argv element, so shell metacharacters in it are inert. A way to
  break any of that is in scope.
- **Escaping the redaction rules through the `registry.toml` overlay**, beyond
  the authority the overlay is documented to have.

Known and by design, so not a vulnerability:

- **`--reveal` prints secrets in full.** That is what it is for. It exists only
  on `show`, and no other flag implies it. Its output is not safe to paste.
- **`--check` makes network calls**, indirectly, by running each provider's own
  CLI. It is off by default; without it credmap never leaves the filesystem.
- **The fingerprint shows the last four characters** of a secret 16 characters
  or longer, plus its length.
- **The overlay at `~/.config/credmap/registry.toml` has your full authority.**
  It can point credmap at any readable file and declare any command for
  `--check`. A group- or world-writable overlay file is refused with a warning;
  the containing directory is not checked, so keep it writable only by you.
- **Symlinks are followed**, and the permission audit reports the target's real
  mode. It is your home directory.
