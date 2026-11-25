# @locksmith/agent-langchain

LangChain.js and LangGraph.js adapter for Locksmith. Apache-2.0. It contains no security logic: the gateway decides, the adapter only filters tools.

## Install

```sh
npm i @locksmith/agent @locksmith/agent-langchain
```

## Quick start

```ts
import { createAgentClient } from "@locksmith/agent";
import { locksmithTools } from "@locksmith/agent-langchain";

const client = createAgentClient(); // LOCKSMITH_ENROLLMENT_SECRET, LOCKSMITH_GATEWAY_URL, LOCKSMITH_CONTROL_PLANE_URL
const tools = await locksmithTools(client); // LangChain tools for `createReactAgent`
```

## Filtered tools

Only `list_my_keys`, `relay_http_request` and `explain_block` are kept. Any other tool (for example `issue_short_lived_credential`) is dropped and reported by name only. If a kept tool's schema has a property whose last word means a value (`value`, `secret`, ...), the adapter throws: an agent must never receive a secret value, only relay requests through the gateway.

## Smoke test

With `just up` and `just api` running: `just agent-smoke langchain`. Unit tests: `just test agent-langchain`.
