# Security Policy

## Reporting a vulnerability
Report vulnerabilities privately through GitHub Security Advisories on this repository (Security tab, "Report a vulnerability"). Do not open public issues, pull requests or discussions for security problems, and never include real secrets in a report.

Please include affected component and version or commit, steps to reproduce, and the impact you see. We aim to acknowledge a report within 3 working days and to agree a fix and disclosure timeline with you.

## Supported versions
Locksmith is pre-release. Only the latest commit on `main` is supported; fixes are not backported.

## Scope
In scope: the vault and crypto code, `locksmithd`, the `smith` CLI, relays and proxies, the audit ledger, the control plane and gateway services, the desktop and web apps, and the agent plugins.

Out of scope: vulnerabilities in third-party dependencies with no Locksmith-specific impact (report upstream), social engineering, denial of service through unrealistic resource use, and issues that need a machine you already fully control.

## What counts as a security bug
Any way for an agent, plugin or remote party to obtain a plaintext secret, bypass session scopes or revocation, tamper with the audit ledger undetected, or make unlock or export fail through licensing, billing or update paths.
