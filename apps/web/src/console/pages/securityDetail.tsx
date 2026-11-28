// Security product: the detail view for one finding.
import { Badge } from "@locksmith-hq/ui/badge";
import { Card } from "@locksmith-hq/ui/card";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { useState } from "react";
import { Crumbs, Empty, Head, Icon, ago } from "../kit";
import { dismiss, href, mask, reopen, resolve, sevLabel, useWorld } from "./securityStore";

export function FindingView({ id, say }: { id: string; say: (note: string) => void }) {
  const [w, setW] = useWorld();
  const [asking, setAsking] = useState(false);
  const f = w.findings.find((x) => x.id === id);
  if (!f) {
    return (
      <section>
        <Crumbs trail={[["Findings", href("findings")], ["Not found"]]} />
        <Empty icon="search">
          <b>No such finding.</b> It may have been removed.{" "}
          <a
            className="ml-auto cursor-pointer rounded-sm py-0.5 text-[13px] font-semibold text-[var(--brand-text)] underline decoration-1 underline-offset-[3px] hover:decoration-2"
            href={href("findings")}
          >
            Back to findings
          </a>
        </Empty>
      </section>
    );
  }
  const [project] = f.secret?.split("/") ?? [];
  const open = f.status === "Open";
  return (
    <section>
      <Crumbs trail={[["Findings", href("findings")], [f.kind]]} />
      <Head title={f.kind} sub={`Found in ${f.srcName}, first seen ${ago(f.first)}. The value is always hidden here.`}>
        {open ? (
          <Button
            type="button"
            onClick={() => {
              setW(resolve(w, f.id));
              say("Marked resolved");
            }}
          >
            Mark resolved
          </Button>
        ) : (
          <Button
            type="button"
            onClick={() => {
              setW(reopen(w, f.id));
              say("Finding reopened");
            }}
          >
            Reopen finding
          </Button>
        )}
      </Head>
      <div className="detail-cols sc-cols">
        <div className="sc-stack">
          <Card className="panel" role="region" aria-labelledby="fd-what">
            <h2 id="fd-what">What and where</h2>
            <dl className="sc-facts">
              {(
                [
                  [
                    "Where",
                    <>
                      {f.srcName}
                      <div className="mono muted">{f.spot}</div>
                    </>,
                  ],
                  ["Added by", f.who],
                  [
                    "Severity",
                    <span key="s" className="sev" data-sev={f.sev.toLowerCase()}>
                      {sevLabel(f)}
                    </span>,
                  ],
                  [
                    "Status",
                    <span key="t">
                      {f.status}
                      {f.rotationOpened && open && <Badge variant="secondary">Rotation opened</Badge>}
                      {f.reason && <span className="muted"> ({f.reason})</span>}
                    </span>,
                  ],
                ] as [string, React.ReactNode][]
              ).map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd>{v}</dd>
                </div>
              ))}
            </dl>
            <h3>Around the line, value hidden</h3>
            <pre className="excerpt mono" aria-label="Code around the finding, with the value hidden">
              {f.lines.map(([n, t, hit]) => (
                <div key={n} data-hit={hit}>
                  <span>{n}</span>
                  <span>{mask(t)}</span>
                </div>
              ))}
            </pre>
          </Card>
        </div>
        <div className="sc-stack">
          <Card className="panel" role="region" aria-labelledby="fd-secret">
            <h2 id="fd-secret">Matching Locksmith secret</h2>
            {f.secret && project ? (
              <>
                <p className="small">
                  <span className="mono strong">{f.secret}</span> is stored in Locksmith.{" "}
                  {f.rotated
                    ? "It has been rotated, so the exposed value no longer works."
                    : "Rotate it so the exposed value stops working."}
                </p>
                {f.rotationOpened && !f.rotated && (
                  <p className="small">A rotation was opened automatically. You still approve the new value.</p>
                )}
                <p style={{ margin: "10px 0 0" }}>
                  <Button asChild variant="outline" size="sm">
                    <a href={`#/secrets/${project}/rotation`}>
                      <Icon name="rotate" />
                      Open rotation for {project}
                    </a>
                  </Button>
                </p>
              </>
            ) : (
              <p className="small muted">
                No Locksmith secret matches this value. Revoke it where it was issued and create a new one.
              </p>
            )}
          </Card>
          <Card className="panel" role="region" aria-labelledby="fd-act">
            <h2 id="fd-act">Not a real secret?</h2>
            {asking ? (
              <form
                className="inline-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  setW(dismiss(w, f.id, String(new FormData(e.currentTarget).get("reason"))));
                  setAsking(false);
                  say("Marked as not a secret");
                }}
              >
                <Input
                  name="reason"
                  aria-label="Why is this not a secret?"
                  placeholder="Why is this not a secret?"
                  required
                  autoFocus
                  autoComplete="off"
                />
                <Button variant="outline" size="sm" type="submit">
                  Save reason
                </Button>
                <Button variant="ghost" size="sm" type="button" onClick={() => setAsking(false)}>
                  Cancel
                </Button>
              </form>
            ) : open ? (
              <Button variant="ghost" size="sm" type="button" onClick={() => setAsking(true)}>
                Not a secret
              </Button>
            ) : (
              <p className="small muted">
                {f.status === "Resolved" ? "This finding is resolved." : "This finding was dismissed."} Reopen it if
                that was a mistake.
              </p>
            )}
          </Card>
        </div>
      </div>
    </section>
  );
}
