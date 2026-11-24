import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, Route, Routes, useParams } from "react-router";
import { Head } from "@locksmith/ui";
import type { Client, Environment, Project, Secret, SecretVersion } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

/** Secret metadata only: names, ids and version counts. No value or material is ever requested. */
function SecretList({ client }: { client: Client }) {
  const projects = useQuery({ queryKey: ["projects"], queryFn: () => client.listProjects() });
  const [pid, setPid] = useState("");
  const [eid, setEid] = useState("");
  const project = pid || projects.data?.[0]?.id || "";
  const envs = useQuery({
    queryKey: ["environments", project],
    queryFn: () => client.listEnvironments(project),
    enabled: !!project,
  });
  const env = eid || envs.data?.[0]?.id || "";
  const secrets = useQuery({
    queryKey: ["secrets", project, env],
    queryFn: () => client.listSecrets(project, env),
    enabled: !!project && !!env,
  });
  return (
    <>
      <Head title="Secrets" />
      <QueryState query={projects} empty="No projects yet, so no secrets.">
        {(ps: Project[]) => (
          <label className="muted">
            Project{" "}
            <select
              aria-label="Project"
              value={project}
              onChange={(e) => {
                setPid(e.target.value);
                setEid("");
              }}
            >
              {ps.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        )}
      </QueryState>
      {project && (
        <QueryState query={envs} empty="No environments in this project.">
          {(es: Environment[]) => (
            <label className="muted">
              Environment{" "}
              <select aria-label="Environment" value={env} onChange={(e) => setEid(e.target.value)}>
                {es.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name}
                  </option>
                ))}
              </select>
            </label>
          )}
        </QueryState>
      )}
      {project && env && (
        <QueryState query={secrets} empty="No secrets in this environment.">
          {(items: Secret[]) => (
            <ul className="list">
              {items.map((s) => (
                <li key={s.id} className="row">
                  <Link to={`/secrets/${project}/${env}/${s.id}`}>{s.name}</Link> ({s.version_count} versions)
                </li>
              ))}
            </ul>
          )}
        </QueryState>
      )}
    </>
  );
}

function SecretDetail({ client }: { client: Client }) {
  const { pid = "", eid = "", sid = "" } = useParams();
  const secret = useQuery({ queryKey: ["secret", pid, eid, sid], queryFn: () => client.getSecret(pid, eid, sid) });
  const versions = useQuery({
    queryKey: ["secret-versions", pid, eid, sid],
    queryFn: () => client.listSecretVersions(pid, eid, sid),
  });
  return (
    <>
      <nav className="crumbs">
        <Link to="/secrets">All secrets</Link>
      </nav>
      <QueryState query={secret}>
        {(s: Secret) => (
          <>
            <Head title={s.name} />
            <p>{s.description}</p>
            <p>Updated {s.updated_at}</p>
          </>
        )}
      </QueryState>
      <h3>Versions</h3>
      <QueryState query={versions} empty="No versions yet.">
        {(vs: SecretVersion[]) => (
          <table className="grid">
            <thead>
              <tr>
                <th>Version</th>
                <th>Key</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {vs.map((v) => (
                <tr key={v.version}>
                  <td>{v.version}</td>
                  <td>{v.key_id}</td>
                  <td>{v.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </QueryState>
    </>
  );
}

export function Secrets({ client }: { client: Client }) {
  return (
    <Routes>
      <Route index element={<SecretList client={client} />} />
      <Route path=":pid/:eid/:sid" element={<SecretDetail client={client} />} />
    </Routes>
  );
}
