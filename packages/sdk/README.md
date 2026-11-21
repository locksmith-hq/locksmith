# @locksmith/sdk

A typed client for the Locksmith control plane, generated from `services/control-plane/openapi.json`
(Apache-2.0, built on `openapi-fetch`).

## Install

It is an npm workspace package: add `"@locksmith/sdk": "*"` to a workspace's `package.json` and run `npm i` there.

## Auth

```ts
import { createLocksmith, unwrap } from "@locksmith/sdk";

const ls = createLocksmith({ baseUrl: "https://hub.example.com", token: () => getToken() });
```

`token` is a string or a function read on every request, so a renewed token is used. The SDK never logs or stores a token or a response body.

## Errors

`unwrap(await ls.GET(...))` returns the data or throws a `LocksmithError` with `status` and the RFC 9457 problem fields (`type`, `title`, `detail`).

## Paging

```ts
import { paginate } from "@locksmith/sdk";

for await (const page of paginate((cursor) =>
  ls.GET("/v1/agents", { params: { query: { cursor } } }).then(unwrap),
)) {
  for (const agent of page.items) console.log(agent.id, agent.name);
}
```

## CI example: create a grant

```ts
unwrap(
  await ls.POST("/v1/agents/{agent_id}/grants", {
    params: { path: { agent_id: process.env.AGENT_ID! } },
    body: { secret_id: process.env.SECRET_ID! },
  }),
);
```

An agent's enrollment secret appears only in the response of `POST /v1/agents`; keep it in memory and hand it straight to the agent.

## Develop

`just sdk-gen` regenerates `src/schema.d.ts`; `just test sdk` runs the tests (including the drift check); `just sdk-smoke` runs the smoke test against `just up`.
