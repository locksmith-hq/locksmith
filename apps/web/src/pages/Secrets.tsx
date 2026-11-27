import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList } from "@locksmith-hq/breadcrumb";
import { Label } from "@locksmith-hq/label";
import { Dropdown, Option } from "../Dropdown";
import { PageHeader } from "@locksmith-hq/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/table";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, Route, Routes, useParams } from "react-router";
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
      <PageHeader title="Secrets" />
      <QueryState query={projects} empty="No projects yet, so no secrets.">
        {(ps: Project[]) => (
          <Label className="mb-3 text-muted-foreground">
            Project{" "}
            <Dropdown
              aria-label="Project"
              value={project}
              onChange={(e) => {
                setPid(e);
                setEid("");
              }}
            >
              {ps.map((p) => (
                <Option key={p.id} value={p.id}>
                  {p.name}
                </Option>
              ))}
            </Dropdown>
          </Label>
        )}
      </QueryState>
      {project && (
        <QueryState query={envs} empty="No environments in this project.">
          {(es: Environment[]) => (
            <Label className="mb-3 text-muted-foreground">
              Environment{" "}
              <Dropdown aria-label="Environment" value={env} onChange={(e) => setEid(e)}>
                {es.map((x) => (
                  <Option key={x.id} value={x.id}>
                    {x.name}
                  </Option>
                ))}
              </Dropdown>
            </Label>
          )}
        </QueryState>
      )}
      {project && env && (
        <QueryState query={secrets} empty="No secrets in this environment.">
          {(items: Secret[]) => (
            <ul className="divide-y rounded-md border bg-card">
              {items.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                  <Link
                    className="font-medium underline-offset-3 hover:underline"
                    to={`/secrets/${project}/${env}/${s.id}`}
                  >
                    {s.name}
                  </Link>{" "}
                  ({s.version_count} versions)
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
      <Breadcrumb className="mb-3">
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <Link to="/secrets">All secrets</Link>
            </BreadcrumbLink>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <QueryState query={secret}>
        {(s: Secret) => (
          <>
            <PageHeader title={s.name} />
            <p>{s.description}</p>
            <p>Updated {s.updated_at}</p>
          </>
        )}
      </QueryState>
      <h3 className="mt-4 mb-2 text-base font-semibold">Versions</h3>
      <QueryState query={versions} empty="No versions yet.">
        {(vs: SecretVersion[]) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Version</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vs.map((v) => (
                <TableRow key={v.version}>
                  <TableCell>{v.version}</TableCell>
                  <TableCell>{v.key_id}</TableCell>
                  <TableCell>{v.created_at}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
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
