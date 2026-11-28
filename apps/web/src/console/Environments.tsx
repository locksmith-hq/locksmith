// The organization's environments. New projects start with this list, and each project inherits them until it says otherwise.
// Each environment has a page of its own, where more settings per environment can go later.
import { Badge } from "@locksmith-hq/ui/badge";
import { Card } from "@locksmith-hq/ui/card";
import { useState } from "react";
import * as seed from "./data";
import { EnvEditor } from "./EnvEditor";
import { Crumbs, Head, plural } from "./kit";

export function Environments({ env, secrets }: { env?: string; secrets: seed.Secret[] }) {
  return env ? <EnvironmentPage env={decodeURIComponent(env)} secrets={secrets} /> : <EnvironmentList />;
}

function EnvironmentList() {
  const [envs, setEnvsNow] = useState(seed.defaults.envs);
  return (
    <section>
      <Head
        title="Environments"
        sub="The environments of this organization. New projects start with them, and a project can keep a list of its own."
      />
      <EnvEditor
        envs={envs}
        setEnvs={(change) => {
          seed.defaults.envs = change(seed.defaults.envs);
          setEnvsNow(seed.defaults.envs);
        }}
        href={(e) => `#/environments/${encodeURIComponent(e)}`}
        about="Every project has these environments, each inherited until the project stops inheriting it. A project can also add environments of its own. The last one is treated as production."
        scope="deletes every secret in it, in every project that still inherits it."
      />
    </section>
  );
}

/** One environment: which projects have it, and room for settings of the environment itself. */
function EnvironmentPage({ env, secrets }: { env: string; secrets: seed.Secret[] }) {
  const using = seed.projects.filter((p) => p.envs.includes(env));
  const isProd = seed.defaults.envs.at(-1) === env;
  if (!seed.defaults.envs.includes(env) && using.length === 0)
    return (
      <p className="state">
        There is no environment named <b>{env}</b>. <a href="#/environments">Back to environments</a>
      </p>
    );
  return (
    <section>
      <Crumbs trail={[["Environments", "#/environments"], [env]]} />
      <Head
        title={env}
        sub={`${plural(using.length, "project")} ${using.length === 1 ? "has" : "have"} this environment.`}
      >
        {isProd && <Badge className="tag-prod">Production</Badge>}
      </Head>
      <Card className="panel">
        <h2>Projects</h2>
        <ul className="plain">
          {using.map((p) => (
            <li key={p.id}>
              <a className="ls-link" href={`#/secrets/${p.id}/secrets/${encodeURIComponent(env)}`}>
                {p.id}
              </a>
              <span className="muted">
                {plural(secrets.filter((s) => s.project === p.id && s.env === env).length, "secret")}
                {" · "}
                {
                  { inherited: "inherited", detached: "stopped inheriting", own: "its own", removed: "" }[
                    seed.envStatus(p, env)
                  ]
                }
              </span>
            </li>
          ))}
          {using.length === 0 && <li className="muted">No project has this environment.</li>}
        </ul>
      </Card>
    </section>
  );
}
