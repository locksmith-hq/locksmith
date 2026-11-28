import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Badge } from "@locksmith-hq/ui/badge";
import { Button } from "@locksmith-hq/ui/button";
import { Card } from "@locksmith-hq/ui/card";
import { Input } from "@locksmith-hq/ui/input";
import { useState } from "react";

/** The environments of a project, or the starting set for new ones: add, remove, and the last one is production. */
export function EnvEditor({
  envs,
  setEnvs,
  about,
  scope,
  href,
}: {
  envs: string[];
  setEnvs: (next: (x: string[]) => string[]) => void;
  about: string;
  /** What removing an environment does, after its name. */
  scope: string;
  /** Makes each environment a link to its own page. */
  href?: (env: string) => string;
}) {
  const [gone, setGone] = useState<string | null>(null);
  // The add row is not a <form>: the page this can sit in may be one, and forms cannot nest.
  const [draft, setDraft] = useState("");
  const add = () => {
    const v = draft
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    if (v && !envs.includes(v)) setEnvs((x) => [...x.slice(0, -1), v, x[x.length - 1]!]);
    setDraft("");
  };
  return (
    <Card className="panel form">
      <h2>Environments</h2>
      <p className="muted">{about}</p>
      <ul className="plain" style={{ margin: "12px 0" }}>
        {envs.map((e, i) => (
          <li key={e}>
            {href ? (
              <a className="mono ls-link" href={href(e)}>
                {e}
              </a>
            ) : (
              <span className="mono">{e}</span>
            )}
            {i === envs.length - 1 && <Badge variant="secondary">Production</Badge>}
            {envs.length > 1 && (
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
        ))}
      </ul>
      {gone && (
        <Alert variant="destructive">
          <AlertDescription>
            Removing {gone} {scope}
            <Button
              variant="destructive"
              size="sm"
              type="button"
              style={{ marginLeft: "auto" }}
              onClick={() => {
                setEnvs((x) => x.filter((e) => e !== gone));
                setGone(null);
              }}
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
  );
}
