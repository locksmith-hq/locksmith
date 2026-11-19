// Workspace settings (mockup, nothing is saved anywhere). Kept to what an owner actually changes:
// the name, how people sign in, getting data out, and deleting the workspace.
import { useState } from "react";
import "./settings.css";

const START = { name: "", password: true, google: true, github: true, twoStep: true };
type S = typeof START;
type Flag = { [K in keyof S]: S[K] extends boolean ? K : never }[keyof S];

const Row = ({ title, about, children }: { title: string; about?: string; children: React.ReactNode }) => (
  <div className="set-row"><div><b>{title}</b>{about && <p>{about}</p>}</div><div className="set-ctl">{children}</div></div>
);

export function Settings({ name, org, say }: { name: string; org: boolean; say: (note: string) => void }) {
  const first: S = { ...START, name };
  const [saved, setSaved] = useState(first);
  const [s, setS] = useState(first);
  const [confirm, setConfirm] = useState("");
  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const set = <K extends keyof S>(k: K, v: S[K]) => setS((x) => ({ ...x, [k]: v }));
  const toggle = (k: Flag, label: string) => (
    <input type="checkbox" className="switch" role="switch" aria-label={label} checked={s[k]} onChange={(e) => set(k, e.target.checked)} />
  );
  const noSignIn = !s.password && !s.google && !s.github;

  return (
    <form className="settings" onSubmit={(e) => { e.preventDefault(); if (noSignIn) return; setSaved(s); say("Settings saved"); }}>
      <div className="screen-head"><div>
        <h1>Settings</h1>
        <p className="lede">{org ? `The name of ${name}, how its people sign in, and how to take its data out.` : "Your personal workspace: its name, how you sign in, and how to take your data out."}</p>
      </div></div>

      <section className="panel" aria-labelledby="set-general">
        <h2 id="set-general">General</h2>
        <Row title={org ? "Organization name" : "Workspace name"} about="Shown in the selector at the top right and on invoices.">
          <input aria-label="Name" value={s.name} onChange={(e) => set("name", e.target.value)} required />
        </Row>
        <Row title="Region" about="Where this workspace's data is stored. It is chosen when the workspace is created and cannot be changed.">
          <span className="fixed">United States (us-east-1)</span>
        </Row>
      </section>

      <section className="panel" aria-labelledby="set-signin">
        <h2 id="set-signin">Sign-in</h2>
        <Row title="Email and password">{toggle("password", "Allow email and password")}</Row>
        <Row title="Google">{toggle("google", "Allow Google sign-in")}</Row>
        <Row title="GitHub">{toggle("github", "Allow GitHub sign-in")}</Row>
        <Row title="Require a second step" about="A code from an authenticator app after the password. Google and GitHub sign-ins use their own second step.">
          {toggle("twoStep", "Require a second step")}
        </Row>
        {noSignIn && <p className="alert" role="alert">Every sign-in method is off. Turn one on, or nobody can sign in.</p>}
      </section>

      <section className="panel" aria-labelledby="set-data">
        <h2 id="set-data">Take your data out</h2>
        <p className="muted">Locksmith's servers cannot read your secret values, so an export is made on your own machine, one project and environment at a time. Only an owner can run it, and each run is recorded in that project's activity.</p>
        <pre className="cmd"><code>smith export acme-api --env production --out acme-api.production.env</code></pre>
        <p className="muted small">The file holds real values. Treat it like the secrets themselves. Export works on every plan and is never blocked by a billing problem.</p>
      </section>

      <section className="panel danger-zone" aria-labelledby="set-danger">
        <h2 id="set-danger">Delete {org ? "this organization" : "this workspace"}</h2>
        <p className="muted">Deletes every project, secret, grant and connection in {name}. Agents lose access at once. This cannot be undone, so export what you need first.</p>
        <div className="inline-form" style={{ marginTop: 12 }}>
          <input aria-label={`Type ${name} to confirm`} placeholder={`Type ${name} to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
          <button type="button" className="btn danger" disabled={confirm !== name}>Delete {name}</button>
        </div>
      </section>

      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <button type="button" className="btn quiet" onClick={() => setS(saved)}>Discard</button>
          <button type="submit" className="btn primary" disabled={noSignIn}>Save changes</button>
        </div>
      )}
    </form>
  );
}
