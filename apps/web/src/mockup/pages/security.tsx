// Security product: findings, sources, rules and settings. Sample data only; nothing is scanned or saved.
// All four pages (and the finding view in securityDetail.tsx) read one shared store in securityStore.ts.
import { Fragment, useState } from "react";
import { Empty, Head, Icon, Switch, ago, plural, type Pages, type PageProps } from "../kit";
import { FindingView } from "./securityDetail";
import {
  href,
  ignored,
  offReason,
  openCount,
  rank,
  reconcile,
  scan,
  sevLabel,
  unid,
  useWorld,
  type Group,
  type Settings,
  type Status,
} from "./securityStore";
import "../settings.css";
import "./security.css";

/* ---------- Findings ---------- */
const STATUSES: (Status | "All")[] = ["All", "Open", "Resolved", "Not a secret"];

// What was found, where, and what to do about it. Open a finding to rotate, resolve or dismiss it.
function FindingList() {
  const [w] = useWorld();
  const [status, setStatus] = useState<Status | "All">("All");
  const [q, setQ] = useState("");
  const rows = w.findings;
  const open = rows.filter((f) => f.status === "Open");
  const crit = open.filter((f) => f.sev === "Critical").length;
  const needle = q.trim().toLowerCase();
  const shown = rows
    .filter((f) => status === "All" || f.status === status)
    .filter(
      (f) =>
        !needle ||
        (f.secret ?? "").toLowerCase().includes(needle) ||
        f.spot.toLowerCase().includes(needle) ||
        f.kind.toLowerCase().includes(needle),
    )
    .sort(
      (a, b) =>
        Number(b.status === "Open") - Number(a.status === "Open") || rank[a.sev] - rank[b.sev] || b.first - a.first,
    );
  const where = (f: (typeof rows)[number]) =>
    f.src === "Repository" ? f.srcName : f.src === "CI log" ? `CI log, ${f.srcName}` : `Transcript of ${f.srcName}`;

  return (
    <section>
      <Head
        title="Findings"
        sub="Secrets that were found in code, builds and agent sessions, and what to do about each one."
      />
      <p className="sec-status" role="status">
        {open.length === 0 ? "No open findings." : `${plural(open.length, "open finding")}, ${crit} critical.`}
      </p>
      <div className="toolbar">
        <label className="field sc-search">
          Search
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Secret name or path"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <fieldset className="seg inline">
          <legend className="sr-only">Status</legend>
          {STATUSES.map((s) => (
            <label key={s}>
              <input type="radio" name="fstatus" checked={status === s} onChange={() => setStatus(s)} />
              {s}
              {s !== "All" && <span className="n">{rows.filter((f) => f.status === s).length}</span>}
            </label>
          ))}
        </fieldset>
      </div>
      {shown.length === 0 ? (
        <Empty icon="shield">
          <b>{rows.length === 0 ? "Nothing found." : "No findings match."}</b>{" "}
          {rows.length === 0 ? "Add a source and scan it." : "Change the search or the status to see the rest."}
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid fnd">
            <thead>
              <tr>
                <th>Found</th>
                <th>Where</th>
                <th>First seen</th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id}>
                  <td>
                    <a className="strong" href={href("findings", f.id)}>
                      {f.kind}
                    </a>
                    {f.secret && (
                      <div className="muted small">
                        Matches <span className="mono">{f.secret}</span>
                      </div>
                    )}
                  </td>
                  <td>
                    {where(f)}
                    <div className="mono muted">{f.spot}</div>
                  </td>
                  <td className="muted">{ago(f.first)}</td>
                  <td>
                    <span className="sev" data-sev={f.sev.toLowerCase()}>
                      {sevLabel(f)}
                    </span>
                  </td>
                  <td className={f.status === "Open" ? "st-open" : "st-done"}>
                    {f.status}
                    {f.status === "Open" && f.rotationOpened && <div className="small">Rotation opened</div>}
                    {f.reason && f.status === "Not a secret" && <div className="small muted">{f.reason}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
function Findings(p: PageProps) {
  return p.sub ? <FindingView id={unid(p.sub)} say={p.say} /> : <FindingList />;
}

/* ---------- Sources ---------- */
const GROUPS: Group[] = ["Repositories", "CI logs", "Agent transcripts"];
const MORE_REPOS = ["acme/docs", "acme/mobile", "acme/data-tools"];

// What is being scanned, grouped by kind, with a switch and a scan button for each.
function Sources({ say }: PageProps) {
  const [w, setW] = useWorld();
  const [adding, setAdding] = useState(false);
  const rows = w.sources;
  const free = MORE_REPOS.filter((r) => !rows.some((s) => s.name === r));
  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const repo = String(f.get("repo"));
    const ci = f.get("what") === "ci";
    setW({
      ...w,
      seq: w.seq + 1,
      sources: [
        ...rows,
        {
          id: `n${w.seq}`,
          name: ci ? `GitHub Actions: ${repo.split("/")[1]}` : repo,
          group: ci ? "CI logs" : "Repositories",
          last: null,
          on: true,
        },
      ],
    });
    setAdding(false);
    say(`Added ${repo}. Press Scan now to run the first scan.`);
  };
  return (
    <section>
      <Head title="Sources" sub="Repositories, build logs and agent sessions that are checked for exposed secrets.">
        <button
          type="button"
          className="btn"
          onClick={() => {
            const r = scan(
              w,
              rows.map((s) => s.id),
            );
            setW(r.world);
            say(r.msg);
          }}
        >
          <Icon name="search" />
          Scan all sources
        </button>
        <button
          type="button"
          className="btn primary"
          onClick={() => setAdding(true)}
          disabled={adding || free.length === 0}
        >
          <Icon name="plus" />
          Add a source
        </button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add a source">
          <h2>Add a source</h2>
          <div className="add share">
            <label className="field">
              Repository
              <select name="repo" autoFocus>
                {free.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
            </label>
            <label className="field">
              Scan
              <select name="what">
                <option value="code">The code</option>
                <option value="ci">Its build logs</option>
              </select>
            </label>
            <button type="submit" className="btn primary">
              Add source
            </button>
            <button type="button" className="btn quiet sc-start" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
          <p className="hint">
            Repositories come from your GitHub connection in Integrations. Locksmith reads them and never changes them.
          </p>
        </form>
      )}
      <p className="sc-note">
        <Icon name="shield" />
        Agent transcripts are scanned for secret patterns only. They are not stored.
      </p>
      {rows.length === 0 ? (
        <Empty icon="git">
          <b>Nothing is being scanned.</b> Add a repository from your GitHub connection to start.
        </Empty>
      ) : (
        GROUPS.map((g) => {
          const list = rows.filter((s) => s.group === g);
          return list.length === 0 ? null : (
            <Fragment key={g}>
              <h2 className="group-h">
                {g}
                <span className="n">{list.length}</span>
              </h2>
              <ul className="list">
                {list.map((s) => {
                  const reason = offReason(s, w.settings);
                  const n = openCount(w, s.id);
                  return (
                    <li key={s.id} className="row sec-row">
                      <span className="ic">
                        <Icon name={g === "Repositories" ? "git" : g === "CI logs" ? "run" : "s_terminal"} />
                      </span>
                      <div>
                        <span className="strong mono">{s.name}</span>
                        <p>{reason ?? `Last scan ${ago(s.last)}`}</p>
                      </div>
                      <span className="sec-meta">
                        <span className="cnt" style={n ? { color: "var(--danger-text)", fontWeight: 600 } : undefined}>
                          {n} open
                        </span>
                        <label className="small sc-sw">
                          <input
                            type="checkbox"
                            className="switch"
                            role="switch"
                            aria-label={`Scan ${s.name}`}
                            checked={s.on && !(g === "Agent transcripts" && !w.settings.transcripts)}
                            disabled={g === "Agent transcripts" && !w.settings.transcripts}
                            onChange={(e) =>
                              setW({
                                ...w,
                                sources: rows.map((x) => (x.id === s.id ? { ...x, on: e.target.checked } : x)),
                              })
                            }
                          />
                          {reason ? "Off" : "On"}
                        </label>
                        <button
                          type="button"
                          className="btn sm"
                          disabled={!!reason}
                          aria-label={`Scan ${s.name} now`}
                          onClick={() => {
                            const r = scan(w, [s.id]);
                            setW(r.world);
                            say(`${s.name}: ${r.msg}`);
                          }}
                        >
                          Scan now
                        </button>
                        <button
                          type="button"
                          className="btn sm quiet danger-text"
                          aria-label={`Remove ${s.name}`}
                          onClick={() => {
                            setW({ ...w, sources: rows.filter((x) => x.id !== s.id) });
                            say(`Removed ${s.name}`);
                          }}
                        >
                          Remove
                        </button>
                      </span>
                    </li>
                  );
                })}
              </ul>
            </Fragment>
          );
        })
      )}
    </section>
  );
}

/* ---------- Rules ---------- */
// What counts as a secret: the built-in detectors, and paths to skip.
function Rules({ say }: PageProps) {
  const [w, setW] = useWorld();
  const [path, setPath] = useState("");
  const count = (id: string) => w.findings.filter((f) => f.rule === id).length;
  const setPaths = (paths: string[], msg: (moved: number) => string) => {
    const r = reconcile(w, paths);
    setW(r.world);
    say(msg(r.moved));
  };
  return (
    <section>
      <Head title="Rules" sub="Decide what counts as a secret: the built-in detectors and the paths to skip." />
      <h2 className="group-h">Built-in detectors</h2>
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              <th>Detector</th>
              <th>What it looks for</th>
              <th className="num">Findings</th>
              <th>On</th>
            </tr>
          </thead>
          <tbody>
            {w.det.map((d) => (
              <tr key={d.id}>
                <td className="strong">{d.name}</td>
                <td className="muted">{d.about}</td>
                <td className="num mono">{count(d.id)}</td>
                <td>
                  <Switch
                    label={`Detect ${d.name}`}
                    checked={d.on}
                    onChange={(on) => {
                      setW({ ...w, det: w.det.map((y) => (y.id === d.id ? { ...y, on } : y)) });
                      say(`${d.name} is ${on ? "on" : "off"}`);
                    }}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h2 className="group-h">
        Ignored paths<span className="n">{w.paths.length}</span>
      </h2>
      <form
        className="inline-form sc-pathform"
        onSubmit={(e) => {
          e.preventDefault();
          const p = path.trim();
          if (p && !w.paths.includes(p))
            setPaths([...w.paths, p], (n) =>
              n
                ? `Ignoring ${p}. Moved ${plural(n, "finding")} to Not a secret.`
                : `Ignoring ${p}. No open finding is in those files.`,
            );
          setPath("");
        }}
      >
        <input
          aria-label="Path to ignore"
          placeholder="vendor/**"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
        <button type="submit" className="btn sm" disabled={!path.trim()}>
          Ignore path
        </button>
      </form>
      {w.paths.length === 0 ? (
        <Empty icon="doc">
          <b>Every file is scanned.</b> Add a path such as <span className="mono">tests/fixtures/**</span> to skip
          sample data.
        </Empty>
      ) : (
        <ul className="list">
          {w.paths.map((p) => {
            const n = w.findings.filter((f) => ignored([p], f)).length;
            return (
              <li key={p} className="row sc-prow">
                <span className="ic">
                  <Icon name="doc" />
                </span>
                <span>
                  <span className="mono">{p}</span>{" "}
                  <span className="muted small">
                    {n === 0 ? "No findings in these files" : `${plural(n, "finding")} in these files`}
                  </span>
                </span>
                <button
                  type="button"
                  className="btn sm quiet danger-text"
                  aria-label={`Stop ignoring ${p}`}
                  onClick={() =>
                    setPaths(
                      w.paths.filter((y) => y !== p),
                      (m) => (m ? `Stopped ignoring ${p}. Reopened ${plural(m, "finding")}.` : `Stopped ignoring ${p}`),
                    )
                  }
                >
                  Remove
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/* ---------- Settings ---------- */
const Row = ({ title, about, children }: { title: string; about: string; children: React.ReactNode }) => (
  <div className="set-row">
    <div>
      <b>{title}</b>
      <p>{about}</p>
    </div>
    <div className="set-ctl">{children}</div>
  </div>
);

// When scans run and what Locksmith does on its own.
function SecuritySettings({ say }: PageProps) {
  const [w, setW] = useWorld();
  const saved = w.settings;
  const [s, setS] = useState<Settings>(saved);
  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const sw = (k: keyof Settings, label: string) => (
    <input
      type="checkbox"
      className="switch"
      role="switch"
      aria-label={label}
      checked={s[k]}
      onChange={(e) => setS((x) => ({ ...x, [k]: e.target.checked }))}
    />
  );
  const tCount = w.sources.filter((x) => x.group === "Agent transcripts").length;
  return (
    <form
      className="settings"
      onSubmit={(e) => {
        e.preventDefault();
        setW({ ...w, settings: s });
        say("Security settings saved");
      }}
    >
      <Head
        title="Settings"
        sub={
          <>
            Choose when scans run and what happens automatically. Who is alerted about a finding is set in{" "}
            <a className="link" href="#/notifications/rules">
              Notification rules
            </a>
            .
          </>
        }
      />
      <section className="panel" aria-labelledby="sec-when">
        <h2 id="sec-when">When to scan</h2>
        <Row title="Scan on every push" about="Checks the new commits on every branch as soon as they arrive.">
          {sw("onPush", "Scan on every push")}
        </Row>
        <Row
          title="Block a merge on a critical finding"
          about="A pull request cannot be merged while a secret that still works is in it."
        >
          {sw("blockMerge", "Block a merge on a critical finding")}
        </Row>
        <Row
          title="Scan agent transcripts"
          about={
            s.transcripts
              ? "Looks for secret patterns in what people paste to agents. Transcripts are not stored."
              : `Off. The ${plural(tCount, "transcript source")} on the Sources page ${tCount === 1 ? "is" : "are"} switched off until you turn this back on.`
          }
        >
          {sw("transcripts", "Scan agent transcripts")}
        </Row>
      </section>
      <section className="panel" aria-labelledby="sec-after">
        <h2 id="sec-after">After a finding</h2>
        <Row
          title="Open a rotation automatically"
          about="When a new finding matches a Locksmith secret, it arrives with a rotation already opened. You still approve the new value."
        >
          {sw("autoRotate", "Open a rotation automatically")}
        </Row>
      </section>
      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <button type="button" className="btn quiet" onClick={() => setS(saved)}>
            Discard
          </button>
          <button type="submit" className="btn primary">
            Save changes
          </button>
        </div>
      )}
    </form>
  );
}

export const pages: Pages = {
  "scan/findings": Findings,
  "scan/sources": Sources,
  "scan/rules": Rules,
  "scan/settings": SecuritySettings,
};
