# Licensing

| Part | License |
|---|---|
| Control plane and gateway (`services/`) | AGPL-3.0-only ([LICENSE](LICENSE)) |
| Libraries, CLI, connectors, SDKs, integrations (`crates/`, `packages/`, `integrations/`) | Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)) |
| Third-party components | Their own licenses ([THIRD_PARTY.md](THIRD_PARTY.md)) |

Everything works without a license. Unlocking, reading, writing and exporting your secrets never depends on a subscription. Paid features are not in this repository: they are separate and private, as are the hosted service, its billing and its license server. The open code gives them places to plug in (`crates/ls-entitlements`, `apps/api/src/paid.ts`, `apps/web/src/console/paid.ts`) and works with nothing plugged in.
