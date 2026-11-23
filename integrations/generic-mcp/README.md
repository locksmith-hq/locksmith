# Locksmith MCP for any MCP client

Two ways to connect a client that has no dedicated Locksmith plugin: the local stdio server
(`locksmith-mcp`, below) or the remote Hub server (further down).

## Local stdio server

`mcp.json` is the snippet (generated from `crates/smith-cli/src/agents.rs`, so it cannot drift):

```json
{
  "mcpServers": {
    "locksmith": {
      "args": [],
      "command": "locksmith-mcp"
    }
  }
}
```

Merge the `locksmith` entry into your client's MCP config (the key is `mcpServers` for most clients;
VS Code-style clients use `servers`). `locksmith-mcp` must be on `PATH`. The snippet holds no
secret, no environment values and no arguments: the server reads the agent token from the
Locksmith home, never from the config.

**Protection: none from this snippet.** A generic client has no pre-tool hook, so nothing blocks
the agent from running `cat .env` or `env` itself. What you lose compared with the Claude Code,
Cursor, Codex, Gemini CLI and Copilot plugins:
- no blocking of shell reads of secret files or environment dumps;
- no blocking of prompts that paste secret values;
- no denial audit entry for blocked attempts.

What you keep: the agent can list its grants and make relayed calls through the MCP tools without
ever holding the secret. Run `smith doctor` to see which agents in the repository are protected.

## Remote Hub server

The Hub serves MCP over Streamable HTTP at `<hub>/mcp` and authorises it with OAuth 2.1 (PKCE), following the MCP authorization specification (revision 2025-11-25). No token or secret goes into a config file.

For Claude Code and Codex, `smith init --hub <hub-url>` writes the entry for you (`--dry-run` shows it first). For any other client:

1. **URL.** Point the client at `<hub>/mcp`, for example `https://hub.example/mcp`. Use https; plain http is only for a local stack on `localhost`.
2. **Discovery.** An unauthenticated request gets `401` with `WWW-Authenticate: Bearer resource_metadata="<hub>/.well-known/oauth-protected-resource/mcp"`. The metadata names the authorization server (the Hub's OIDC issuer). A conformant client follows it by itself.
3. **Client registration.** Use the documented pre-registered public client:
   - client id: `locksmith-mcp`
   - public client, no secret, PKCE `S256`
   - redirect: a loopback URL, `http://localhost:<port>/callback` or `http://127.0.0.1:<port>/callback` (any port)
   - consent is required on first sign-in

   Dynamic Client Registration and Client ID Metadata Documents only work where your issuer enables them; the pre-registered client always works.
4. **Resource indicator.** Send `resource=<hub>/mcp` on the authorization and token requests (RFC 8707). The access token's audience is the MCP URL, so a console token is refused on `/mcp` and the reverse.
5. **Tokens.** The client sends `Authorization: Bearer <access token>` on every request. Keep tokens in the client's keychain; never paste one into a config file. Revoking the client in the Hub console refuses its tokens on the next call.

The generated examples are `integrations/claude-code/.mcp.hub.json` and `integrations/codex/config.hub.toml`.
