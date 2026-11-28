// Lifecycle pages inside one Secret Management project: dynamic secrets, history, rotation, syncs. Sample data only.
// All four read one store per project (lifecycleStore), so a change on one page shows on the others.
import { Badge } from "@locksmith-hq/ui/badge";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Label } from "@locksmith-hq/ui/label";
import { Card } from "@locksmith-hq/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { Dropdown, Option } from "../../Dropdown";
import { Fragment, useState, type FormEvent } from "react";
import { Empty, Head, Icon, NOW, DAY, ago, plural, Switch, secrets, type PageProps, type Pages } from "../kit";
import { connections } from "../data";
import {
  ACT_ICON,
  addSync,
  canRoll,
  dest,
  envsOf,
  pid,
  removeSync,
  rollback,
  setSync,
  syncNow,
  syncState,
  useP,
  type Entry,
} from "./lifecycleStore";
import { RollbackAsk } from "./lifecycleUi";
import "./lifecycle.css";

/* ---------- History ---------- */
// Page: every change to this project's secrets and settings as a timeline by day, with a way back to an earlier state.
function History({ project, say }: PageProps) {
  const p = pid(project);
  const [s, up] = useP(p);
  const [env, setEnv] = useState("All");
  const [q, setQ] = useState("");
  const [asking, setAsking] = useState<string | null>(null);
  const base = s.hist.filter((h) => h.name.toLowerCase().includes(q.trim().toLowerCase()));
  const shown = base.filter((h) => env === "All" || h.env === env);
  const filtered = env !== "All" || q !== "";
  const days: [string, Entry[]][] = [];
  for (const r of shown) {
    const n = Math.max(0, Math.floor((NOW - r.at) / DAY));
    const label = n === 0 ? "Today" : n === 1 ? "Yesterday" : `${n} days ago`;
    const g = days.find((d) => d[0] === label);
    if (g) g[1].push(r);
    else days.push([label, [r]]);
  }
  return (
    <section>
      <Head
        title="History"
        sub={`Every change to the secrets and lifecycle settings in ${p}: who did it and what changed. Values are never shown.`}
      />
      <div className="toolbar">
        <ToggleGroup type="single" value={String(env)} aria-label="Environment">
          {["All", ...envsOf(p)].map((e) => (
            <ToggleGroupItem key={e} size="sm" value={String(e)} onClick={() => setEnv(e)}>
              {e}
              <span className="n">{e === "All" ? base.length : base.filter((r) => r.env === e).length}</span>
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <label className="search">
          <span className="sr-only">Find by secret name</span>
          <Icon name="search" />
          <Input type="search" placeholder="Find by name" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>
      {days.length === 0 ? (
        <Empty icon="clock">
          {filtered ? (
            <>
              <b>Nothing matches these filters.</b>{" "}
              <Button
                variant="outline"
                size="sm"
                type="button"
                onClick={() => {
                  setEnv("All");
                  setQ("");
                }}
              >
                Clear filters
              </Button>
            </>
          ) : (
            <>
              <b>No changes in {p}.</b> Add or change a secret and it shows up here.
            </>
          )}
        </Empty>
      ) : (
        days.map(([label, items]) => (
          <Fragment key={label}>
            <h3 className="lc-day">{label}</h3>
            <ul className="list">
              {items.map((e) => (
                <li key={e.id} className="row lc-row" data-undone={e.undone ? "true" : undefined}>
                  <span className="ic">
                    <Icon name={ACT_ICON[e.act]} />
                  </span>
                  <div>
                    <b>{e.act}</b> <span className="mono">{e.name}</span>{" "}
                    {e.env && <Badge variant="secondary">{e.env}</Badge>}
                    <p>
                      {e.who}: {e.note}
                    </p>
                    {asking === e.id && (
                      <RollbackAsk
                        s={s}
                        e={e}
                        onCancel={() => setAsking(null)}
                        onApply={() => {
                          up((x) => rollback(x, p, e));
                          setAsking(null);
                          say(`Rolled back ${e.name} in ${e.env}`);
                        }}
                      />
                    )}
                  </div>
                  <span className="meta">
                    <span title="Time of the change">{ago(e.at)}</span>
                    {e.undone ? (
                      <span className="lc-st">Undone</span>
                    ) : (
                      canRoll(s, e) && (
                        <Button
                          variant="outline"
                          size="sm"
                          type="button"
                          aria-expanded={asking === e.id}
                          aria-label={`Roll back ${e.name} in ${e.env} to here`}
                          onClick={() => setAsking(asking === e.id ? null : e.id)}
                        >
                          Roll back to here
                        </Button>
                      )
                    )}
                  </span>
                </li>
              ))}
            </ul>
          </Fragment>
        ))
      )}
    </section>
  );
}

/* ---------- Syncs ---------- */
const syncTargets = connections.filter((c) => c.kind === "Source and CI" || c.kind === "Cloud");

// Page: copies of an environment's secrets pushed to where apps run, shown as source to destination.
function Syncs({ project, say }: PageProps) {
  const p = pid(project);
  const envs = envsOf(p);
  const [s, up] = useP(p);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const count = (env: string) => secrets.filter((x) => x.project === p && x.env === env).length;
  const add = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const c = syncTargets.find((t) => t.id === f.get("conn"));
    if (!c) return;
    up((x) =>
      addSync(x, p, {
        id: `y_${crypto.randomUUID().slice(0, 6)}`,
        env: String(f.get("env")),
        c,
        target: String(f.get("target")),
        on: true,
      }),
    );
    say(`Added a sync to ${dest(c)}`);
    setAdding(false);
  };
  return (
    <section>
      <Head
        title="Syncs"
        sub={`Keep copies of ${p} secrets where your apps run. Locksmith pushes again each time a secret changes.`}
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Add sync
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={add} aria-label="Add sync">
            <h2>Add a sync</h2>
            <div className="add lc-add">
              <Label className="field">
                Copy from
                <Dropdown name="env">
                  {envs.map((e) => (
                    <Option key={e}>{e}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                To connection
                <Dropdown name="conn">
                  {syncTargets.map((c) => (
                    <Option key={c.id} value={c.id}>
                      {c.name} ({dest(c)})
                    </Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Target
                <Input name="target" required placeholder="acme/api-service" autoComplete="off" />
              </Label>
              <Button type="submit">Add and sync</Button>
              <Button variant="ghost" type="button" onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">
              The first push happens now. The destination then holds real values, so anyone who can read it can read
              them. Locksmith can only push; it never reads them back.
            </p>
          </form>
        </Card>
      )}
      {s.syncs.length === 0 ? (
        <Empty icon="relay">
          <b>No syncs in {p}.</b> Add one to push an environment to GitHub Actions, Vercel or AWS so the app can read it
          there.
        </Empty>
      ) : (
        <ul className="list">
          {s.syncs.map((y) => {
            const st = syncState(s, p, y);
            return (
              <li key={y.id} className="row lc-row">
                <span className="ic">
                  <Icon name={y.c.icon} />
                </span>
                <div>
                  <span className="lc-route">
                    <b>{y.env}</b>
                    <Icon name="arrow" />
                    <b>{dest(y.c)}</b>
                    <span className="mono small">{y.target}</span>
                  </span>
                  <p>
                    <span className="lc-st" data-t={st.tone}>
                      {st.text}
                    </span>{" "}
                    · {plural(count(y.env), "secret")} · last run {ago(y.at)} · via {y.c.name}
                  </p>
                  {removing === y.id && (
                    <Alert variant="destructive" style={{ margin: "10px 0 0" }}>
                      <AlertDescription>
                        Removing this stops copying {plural(count(y.env), "secret")} to {dest(y.c)}. What is already
                        there stays and goes stale; Locksmith does not delete it.
                        <Button
                          variant="destructive"
                          size="sm"
                          type="button"
                          onClick={() => {
                            up((x) => removeSync(x, y.id));
                            setRemoving(null);
                            say("Removed the sync");
                          }}
                        >
                          Remove sync
                        </Button>
                        <Button variant="ghost" size="sm" type="button" onClick={() => setRemoving(null)}>
                          Keep
                        </Button>
                      </AlertDescription>
                    </Alert>
                  )}
                </div>
                <span className="meta">
                  <Switch
                    label={`Keep ${y.env} synced to ${y.target}`}
                    checked={y.on}
                    keyed
                    onChange={(on) => {
                      up((x) => setSync(x, y.id, { on }));
                      say(on ? "Sync resumed" : "Sync paused. Nothing is pushed until you resume");
                    }}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    type="button"
                    disabled={!y.on}
                    aria-label={`Sync ${y.env} to ${y.target} now`}
                    onClick={() => {
                      up((x) => syncNow(x, y.id));
                      say(
                        y.fail
                          ? `Still failing: ${y.fail}`
                          : `Synced ${plural(count(y.env), "secret")} to ${dest(y.c)}`,
                      );
                    }}
                  >
                    Sync now
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-(--destructive-text)"
                    type="button"
                    aria-label={`Remove sync of ${y.env} to ${y.target}`}
                    onClick={() => setRemoving(y.id)}
                  >
                    Remove
                  </Button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

export const pages: Pages = {
  "secrets/history": History,
  "secrets/syncs": Syncs,
};
