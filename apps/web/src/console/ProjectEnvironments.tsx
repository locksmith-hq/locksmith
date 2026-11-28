// The environments of one project. The organization's environments are inherited: they cannot be changed here
// until the project stops inheriting that environment (its switch). Environments of the project's own can always be
// added and removed.
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Badge } from "@locksmith-hq/ui/badge";
import { Button } from "@locksmith-hq/ui/button";
import { Card } from "@locksmith-hq/ui/card";
import { Input } from "@locksmith-hq/ui/input";
import { useState } from "react";
import * as seed from "./data";
import { Head, Switch } from "./kit";

const without = (xs: string[], x: string) => xs.filter((v) => v !== x);

export function ProjectEnvironments({ p }: { p: seed.Project }) {
  const [, redraw] = useState(0);
  const [gone, setGone] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const change = (f: () => void) => {
    f();
    redraw((n) => n + 1);
  };
  const production = p.envs.at(-1);
  const removed = seed.defaults.envs.filter((e) => seed.envStatus(p, e) === "removed");

  // Switch on: follow the organization again. Off: the environment becomes the project's to change.
  const inherit = (e: string, on: boolean) =>
    change(() => {
      p.own = on ? without(p.own, e) : [...p.own, e];
      p.removed = without(p.removed, e);
    });
  const remove = (e: string) =>
    change(() => {
      p.own = without(p.own, e);
      if (seed.defaults.envs.includes(e)) p.removed = [...p.removed, e];
      setGone(null);
    });
  const add = () => {
    const v = draft
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    if (v && !p.envs.includes(v) && !removed.includes(v)) change(() => (p.own = [...p.own, v]));
    setDraft("");
  };

  return (
    <section>
      <Head
        title="Environments"
        sub={`What ${p.id} can keep secrets in. It inherits the organization's environments; stop inheriting one to change or remove it here.`}
      />
      <Card className="panel form">
        <h2>Environments</h2>
        <p className="muted">
          Each environment holds its own set of secrets. The last one is treated as production: access to it can be made
          to need a second person.
        </p>
        <ul className="plain" style={{ margin: "12px 0" }}>
          {p.envs.map((e) => {
            const status = seed.envStatus(p, e);
            return (
              <li key={e}>
                <a className="mono ls-link" href={`#/secrets/${p.id}/secrets/${encodeURIComponent(e)}`}>
                  {e}
                </a>
                {e === production && <Badge variant="secondary">Production</Badge>}
                {status === "inherited" && <Badge variant="outline">Inherited</Badge>}
                {status !== "own" && (
                  <Switch label={`Inherit ${e}`} checked={status === "inherited"} onChange={(on) => inherit(e, on)} />
                )}
                {status !== "inherited" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-(--destructive-text)"
                    type="button"
                    aria-label={`Remove environment ${e}`}
                    onClick={() => setGone(e)}
                  >
                    Remove
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
        {gone && (
          <Alert variant="destructive">
            <AlertDescription>
              Removing {gone} deletes every secret in it and the access agents have to them.
              <Button
                variant="destructive"
                size="sm"
                type="button"
                style={{ marginLeft: "auto" }}
                onClick={() => remove(gone)}
              >
                Remove {gone}
              </Button>
              <Button variant="ghost" size="sm" type="button" onClick={() => setGone(null)}>
                Keep
              </Button>
            </AlertDescription>
          </Alert>
        )}
        <div className="inline-form">
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add();
              }
            }}
            aria-label="New environment name"
            placeholder="preview"
            autoComplete="off"
            spellCheck={false}
          />
          <Button variant="outline" size="sm" type="button" onClick={add}>
            Add environment
          </Button>
        </div>
      </Card>
      {removed.length > 0 && (
        <Card className="panel">
          <h2>Removed from this project</h2>
          <p className="muted">Organization environments this project no longer has. Inherit one to bring it back.</p>
          <ul className="plain" style={{ margin: "12px 0 0" }}>
            {removed.map((e) => (
              <li key={e}>
                <span className="mono">{e}</span>
                <Switch label={`Inherit ${e}`} checked={false} onChange={(on) => inherit(e, on)} />
              </li>
            ))}
          </ul>
        </Card>
      )}
    </section>
  );
}
