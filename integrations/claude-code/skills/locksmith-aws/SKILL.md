---
name: locksmith-aws
description: Use when a command needs AWS credentials (aws cli, terraform, SDK calls, deploys) or fails with missing or expired AWS credentials in a Locksmith project.
---

# AWS

Two paths, both need a session with the `aws` scope and an `[aws.profiles.<name>]` in `.locksmith.toml`:

- Preferred, relay: `smith run --aws <profile> -- <command>`. The command gets dummy AWS credentials; Locksmith signs its AWS calls with the real ones, so the real keys are never in the process.
- Contained: `smith aws creds --contained [--profile <name>] -- <command>`. Short-lived STS credentials are given to that command only (visible to it, so use it only when the relay path cannot work). `--contained` is a required acknowledgement that the command sees them.

Never print the environment (`env`, `printenv`, `set`) of such a command, never write the credentials to files, and never read `~/.aws/credentials`. If the profile is missing or access is denied, tell the human; do not try other profiles.
