// The organization's environments. New projects start with this list, and projects that inherit it follow it.
// Its own page so each environment can get settings of its own later.
import { useState } from "react";
import * as seed from "./data";
import { EnvEditor } from "./EnvEditor";
import { Head } from "./kit";

export function Environments() {
  const [envs, setEnvsNow] = useState(seed.defaults.envs);
  const inheriting = seed.projects.filter((p) => p.inherit).length;
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
        about={`${inheriting === 0 ? "No project inherits them now." : `${inheriting} ${inheriting === 1 ? "project inherits" : "projects inherit"} them, so a change here applies to ${inheriting === 1 ? "it" : "them"} at once.`} The last one is treated as production.`}
        scope="deletes every secret in it, in every project that inherits these."
      />
    </section>
  );
}
