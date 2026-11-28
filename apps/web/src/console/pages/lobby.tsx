// Secret Management lobby: what needs attention across projects, and how each project stands.
// Secrets and grants come from the same store as the Agent Gateway Grants page, so a fix here shows there.
import { Button } from "@locksmith-hq/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { useState } from "react";
import { Empty, Head, Icon, NOW, DAY, ago, plural, projects, type PageProps, type Pages } from "../kit";
import { useSecrets, type Secret } from "./gateway-data";
import "./lobby.css";

type Kind = "stale" | "noexpiry" | "unused";
const KINDS: Record<Kind, { label: string; why: (s: Secret) => string }> = {
  stale: { label: "Not updated in 90 days", why: (s) => `Last changed ${ago(s.updated)}. Add a new version.` },
  noexpiry: {
    label: "Grant with no expiry",
    why: (s) =>
      `${s.grants
        .filter((g) => g.expires === null)
        .map((g) => g.agent)
        .join(", ")} can use it until someone revokes it.`,
  },
  unused: {
    label: "Never used",
    why: (s) =>
      s.grants.length > 0
        ? `No agent has used it, yet ${plural(s.grants.length, "agent")} can. Remove the grants or delete it.`
        : "No agent or sync has read it. Delete it if you no longer need it.",
  },
};
const attentionOf = (ss: Secret[]) =>
  ss.flatMap((s) => {
    const out: { id: string; kind: Kind; s: Secret }[] = [];
    const add = (kind: Kind) => out.push({ id: `${s.id}-${kind}`, kind, s });
    if (NOW - s.updated >= 90 * DAY) add("stale");
    if (s.grants.some((g) => g.expires === null)) add("noexpiry");
    if (s.lastUsed === null) add("unused");
    return out;
  });

// Secret Management overview: what to fix first across every project, then a line per project.
function Overview({ say }: PageProps) {
  const [secs, setSecs] = useSecrets();
  const [confirm, setConfirm] = useState<string | null>(null);
  const open = attentionOf(secs);
  const edit = (id: string, f: (s: Secret) => Secret) => setSecs((ss) => ss.map((s) => (s.id === id ? f(s) : s)));
  const rows = projects.map((p) => {
    const ss = secs.filter((s) => s.project === p.id);
    return {
      p,
      n: ss.length,
      agents: new Set(ss.flatMap((s) => s.grants.map((g) => g.agent))).size,
      last: ss.length ? Math.max(...ss.map((s) => s.updated)) : null,
    };
  });

  // The fix beside an item. Each one changes the shared secrets, so Grants and the projects table agree at once.
  const fix = (a: (typeof open)[number]) => {
    const { s } = a;
    const where = `${s.name} in ${s.project}/${s.env}`;
    if (a.kind === "noexpiry")
      return (
        <Button
          variant="outline"
          size="sm"
          type="button"
          aria-label={`Set expiry to 7 days for ${where}`}
          onClick={() => {
            edit(s.id, (x) => ({
              ...x,
              grants: x.grants.map((g) => (g.expires === null ? { ...g, expires: NOW + 7 * DAY } : g)),
            }));
            say(`Grants on ${s.name} now expire in 7 days`);
          }}
        >
          Set expiry to 7 days
        </Button>
      );
    if (a.kind === "unused" && s.grants.length > 0)
      return (
        <Button
          variant="outline"
          size="sm"
          type="button"
          aria-label={`Remove unused grants for ${where}`}
          onClick={() => {
            edit(s.id, (x) => ({ ...x, grants: [] }));
            say(`Removed ${plural(s.grants.length, "grant")} from ${s.name}`);
          }}
        >
          Remove unused {s.grants.length === 1 ? "grant" : "grants"}
        </Button>
      );
    if (a.kind === "unused")
      return (
        <Button
          variant="destructive"
          size="sm"
          type="button"
          aria-label={`Delete ${where}`}
          onClick={() => setConfirm(a.id)}
        >
          Delete secret
        </Button>
      );
    return null;
  };

  return (
    <section>
      <Head title="Overview" sub="What to look at first across all your projects, and how each project stands." />
      <div className="sec-h">
        <h2>Needs attention</h2>
        <span className="n">{plural(open.length, "item")}</span>
      </div>
      {open.length === 0 ? (
        <Empty icon="shield">
          <b>Nothing needs attention.</b> New items appear here as secrets age or are shared.
        </Empty>
      ) : (
        <ul className="list">
          {open.map((a) => (
            <li key={a.id} className="row lb-row">
              <span className="ic">
                <Icon name={a.kind === "unused" ? "search" : a.kind === "stale" ? "clock" : "alert"} />
              </span>
              <div>
                <a href={`#/secrets/${a.s.project}`} className="strong mono">
                  {a.s.name}
                </a>{" "}
                <span className="muted small">
                  {a.s.project} / {a.s.env}
                </span>
                <p>
                  <span className="prod">{KINDS[a.kind].label}.</span> {KINDS[a.kind].why(a.s)}
                </p>
                {confirm === a.id && (
                  <p className="lb-confirm" role="alert">
                    Delete {a.s.name} from {a.s.project}/{a.s.env}? Its versions go with it and this cannot be undone.
                    <Button
                      variant="destructive"
                      size="sm"
                      type="button"
                      onClick={() => {
                        setSecs((ss) => ss.filter((x) => x.id !== a.s.id));
                        setConfirm(null);
                        say(`Deleted ${a.s.name}`);
                      }}
                    >
                      Delete secret
                    </Button>
                    <Button variant="ghost" size="sm" type="button" onClick={() => setConfirm(null)}>
                      Keep it
                    </Button>
                  </p>
                )}
              </div>
              <span className="meta">{confirm !== a.id && fix(a)}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="sec-h" style={{ marginTop: 28 }}>
        <h2>Projects</h2>
        <span className="n">{projects.length}</span>
      </div>
      <div className="table-wrap">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Project</TableHead>
              <TableHead>Environments</TableHead>
              <TableHead className="num">Secrets</TableHead>
              <TableHead className="num">Agents with access</TableHead>
              <TableHead>Last change</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map(({ p, n, agents, last }) => (
              <TableRow key={p.id}>
                <TableCell>
                  <a href={`#/secrets/${p.id}`} className="strong">
                    {p.id}
                  </a>
                </TableCell>
                <TableCell className="muted">{p.envs.join(", ")}</TableCell>
                <TableCell className="num mono">{n}</TableCell>
                <TableCell className="num mono">{agents}</TableCell>
                <TableCell className="muted">{last === null ? "No secrets" : ago(last)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}

export const pages: Pages = { "secrets-lobby/overview": Overview };
