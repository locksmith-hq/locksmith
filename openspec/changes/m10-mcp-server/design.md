# Design: M10 MCP Server

## Decisions

### D1. Human input never transits the MCP channel
The value is captured by a separate UI process owned by the daemon: the desktop app if it is
running, otherwise a native dialog (macOS `osascript` secure text field, Linux `zenity --password`,
a TTY fallback via `/dev/tty` of the session's terminal). The MCP response schema has no field that
could carry a value. A schema test enforces this, like the M3 protocol test.

### D2. Prompt-injection resistance
Requests from the agent are rendered to the human with the agent-supplied purpose text clearly
marked as "agent says". Provider and key names are validated against the catalog, and URLs in the
purpose text are not clickable. Rate limit: 3 pending requests per session.

## Risks / Trade-offs
- Agents may spam requests. The rate limit and the decline-all button cover this.
