// Workspace settings (sample data, nothing is saved anywhere). Kept to what an owner actually changes:
// the name, how people sign in, getting data out, and deleting the workspace.
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Card } from "@locksmith-hq/ui/card";
import { Switch } from "./kit";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { useState } from "react";
import { FEATURES, GateBadge, useLocked, type Feature } from "./plans";
import "./settings.css";

const START = { name: "", password: true, google: true, github: true, twoStep: true };
type S = typeof START;
type Flag = { [K in keyof S]: S[K] extends boolean ? K : never }[keyof S];

// A setting that not every plan has: its switch or button when the plan includes it, and the way to get it
// when it does not. The row is always shown, so people can see the feature exists.
function Paid({ feature, action }: { feature: Feature; action: string }) {
  const f = FEATURES[feature];
  return useLocked(feature) ? (
    <Button asChild variant="outline" size="sm">
      {f.plan === "Enterprise" ? (
        <a href="mailto:sales@locksmith.example">Talk to us</a>
      ) : (
        <a href="#/billing">See plans</a>
      )}
    </Button>
  ) : (
    <Button variant="outline" size="sm" type="button">
      {action}
    </Button>
  );
}

const Row = ({
  title,
  about,
  needs,
  children,
}: {
  title: string;
  about?: string;
  /** The feature this row needs; its plan is shown beside the title while the plan lacks it. */
  needs?: Feature;
  children: React.ReactNode;
}) => (
  <div className="set-row">
    <div>
      <b>{title}</b> {needs && <GateBadge feature={needs} />}
      {about && <p>{about}</p>}
    </div>
    <div className="set-ctl">{children}</div>
  </div>
);

export function Settings({ name, org, say }: { name: string; org: boolean; say: (note: string) => void }) {
  const first: S = { ...START, name };
  const [saved, setSaved] = useState(first);
  const [s, setS] = useState(first);
  const [confirm, setConfirm] = useState("");
  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const set = <K extends keyof S>(k: K, v: S[K]) => setS((x) => ({ ...x, [k]: v }));
  const toggle = (k: Flag, label: string) => <Switch label={label} checked={s[k]} onChange={(on) => set(k, on)} />;
  const noSignIn = !s.password && !s.google && !s.github;

  return (
    <form
      className="settings"
      onSubmit={(e) => {
        e.preventDefault();
        if (noSignIn) return;
        setSaved(s);
        say("Settings saved");
      }}
    >
      <div className="screen-head">
        <div>
          <h1>Settings</h1>
          <p className="lede">
            {org
              ? `The name of ${name} and how its people sign in.`
              : "Your personal workspace: its name and how you sign in."}
          </p>
        </div>
      </div>

      <Card className="panel" role="region" aria-labelledby="set-general">
        <h2 id="set-general">General</h2>
        <Row
          title={org ? "Organization name" : "Workspace name"}
          about="Shown in the selector at the top right and on invoices."
        >
          <Input aria-label="Name" value={s.name} onChange={(e) => set("name", e.target.value)} required />
        </Row>
        <Row
          title="Region"
          about="Where this workspace's data is stored. It is chosen when the workspace is created and cannot be changed."
        >
          <span className="set-fixed">United States (us-east-1)</span>
        </Row>
      </Card>

      <Card className="panel" role="region" aria-labelledby="set-signin">
        <h2 id="set-signin">Sign-in</h2>
        <Row title="Email and password">{toggle("password", "Allow email and password")}</Row>
        <Row title="Google">{toggle("google", "Allow Google sign-in")}</Row>
        <Row title="GitHub">{toggle("github", "Allow GitHub sign-in")}</Row>
        <Row
          title="Require a second step"
          about="A code from an authenticator app after the password. Google and GitHub sign-ins use their own second step."
        >
          {toggle("twoStep", "Require a second step")}
        </Row>
        <Row title="Single sign-on" about={FEATURES.sso.about} needs="sso">
          <Paid feature="sso" action="Set up" />
        </Row>
        <Row title="User provisioning" about={FEATURES.scim.about} needs="scim">
          <Paid feature="scim" action="Set up" />
        </Row>
        {noSignIn && (
          <Alert variant="destructive">
            <AlertDescription>Every sign-in method is off. Turn one on, or nobody can sign in.</AlertDescription>
          </Alert>
        )}
      </Card>

      <Card className="panel" role="region" aria-labelledby="set-audit">
        <h2 id="set-audit">Audit</h2>
        <Row
          title="Audit file export"
          about="Export the audit ledger as a file, with its proof that nothing was changed. In every plan."
        >
          <Button variant="outline" size="sm" type="button">
            Export
          </Button>
        </Row>
        <Row title="Audit streaming" about={FEATURES.streaming.about} needs="streaming">
          <Paid feature="streaming" action="Set up" />
        </Row>
      </Card>

      <Card className="panel danger-zone" role="region" aria-labelledby="set-danger">
        <h2 id="set-danger">Delete {org ? "this organization" : "this workspace"}</h2>
        <p className="muted">
          Deletes every project, secret, grant and connection in {name}. Agents lose access at once. This cannot be
          undone, so export what you need first.
        </p>
        <div className="inline-form" style={{ marginTop: 12 }}>
          <Input
            aria-label={`Type ${name} to confirm`}
            placeholder={`Type ${name} to confirm`}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="off"
          />
          <Button variant="destructive" type="button" disabled={confirm !== name}>
            Delete {name}
          </Button>
        </div>
      </Card>

      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <Button variant="ghost" type="button" onClick={() => setS(saved)}>
            Discard
          </Button>
          <Button type="submit" disabled={noSignIn}>
            Save changes
          </Button>
        </div>
      )}
    </form>
  );
}
