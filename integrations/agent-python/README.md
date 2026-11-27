# locksmith-agent

The thin Locksmith agent client for Python (Apache-2.0). It holds the agent's identity (the enrolment secret) and
renews a short-lived gateway token; it never returns a secret value. The framework adapters build on it.

## Install

```sh
uv add locksmith-agent   # needs Python 3.10 or newer
```

## Quick start

```python
from locksmith_agent import AgentClient

with AgentClient() as client:  # LOCKSMITH_GATEWAY_URL and LOCKSMITH_ENROLLMENT_SECRET
    print([g["secret_name"] for g in client.list_grants()])
```

## Filtered tools

`pick_allowed_tools` keeps only `list_my_keys`, `relay_http_request` and `explain_block` (`ALLOWED_TOOLS`), and
`assert_no_value_tools` raises `AgentError("unsafe_tool")` if a kept tool has a value-shaped input property. The
token is added only for the gateway origin (`client.auth`), on every request, so it renews and never sits in a
static header.

## Smoke test

With `just up` and `just api` running: `just agent-smoke python`. Unit tests: `just test agent-python`.
