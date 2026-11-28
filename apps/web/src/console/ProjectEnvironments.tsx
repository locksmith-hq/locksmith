// The environments of one project. The organization's environments are inherited: they cannot be changed here.
// Turning an environment's switch off gives the project a copy of its own, which can be changed or removed but never
// goes back to being inherited. Environments of the project's own can always be added and removed.
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
  const [copying, setCopying] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const change = (f: () => void) => {
    f();
    redraw((n) => n + 1);
  };
  const production = p.envs.at(-1);

  // One way: the project gets a copy of the environment, which stays when the organization's changes.
  const copy = (e: string) =>
    change(() => {
      p.own = [...p.own, e];
      setCopying(null);
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
    if (v && !p.envs.includes(v))
      change(() => {
        p.own = [...p.own, v];
        p.removed = without(p.removed, v); // a name the organization has, added again, is a new copy
      });
    setDraft("");
  };

  return (
    <section>
      <Head
        title="Environments"
        sub={`What ${p.id} can keep secrets in. It inherits the organization's environments; stop inheriting one to get a copy you can change or remove.`}
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
                {status === "detached" && <Badge variant="outline">Copy</Badge>}
                {status === "inherited" && <Switch label={`Inherit ${e}`} checked onChange={() => setCopying(e)} />}
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
        {copying && (
          <Alert>
            <AlertDescription>
              Stop inheriting {copying}? {p.id} gets a copy of it that stays as it is when the organization changes{" "}
              {copying}. A copy cannot be inherited again.
              <Button size="sm" type="button" style={{ marginLeft: "auto" }} onClick={() => copy(copying)}>
                Make a copy
              </Button>
              <Button variant="ghost" size="sm" type="button" onClick={() => setCopying(null)}>
                Keep inheriting
              </Button>
            </AlertDescription>
          </Alert>
        )}
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
    </section>
  );
}
