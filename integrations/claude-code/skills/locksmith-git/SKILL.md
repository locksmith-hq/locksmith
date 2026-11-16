---
name: locksmith-git
description: Use when git clone, fetch or push to a private repository or GitHub Enterprise host fails with an authentication error, or when asked to set up Git access without a personal access token.
---

# Git without a token

Locksmith runs a Git forwarder that supplies the credential for private hosts; you never hold a Git token. Needs a session with the `git` scope.

- Setup (once, by or with the human): `smith git setup [--repo|--global] [--host git.example.com]` adds an `include.path` to Git config. `smith git status` shows the forwarder and where it is installed; `smith git teardown` removes it.
- After setup use normal `git clone/fetch/push`. Do not put tokens in remote URLs, do not run `git config credential.*` yourself and do not read `~/.git-credentials`.
- Auth failure: run `smith git status`, then check `locksmith_status` for a live session with `git`. If still blocked, follow `locksmith-blocked`.
- For GitHub CLI use `smith gh ...` (token injected, visible to `gh` only, output redacted).
