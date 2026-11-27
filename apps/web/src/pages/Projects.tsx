import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList } from "@locksmith-hq/breadcrumb";
import { Alert, AlertDescription } from "@locksmith-hq/alert";
import { Button } from "@locksmith-hq/button";
import { Input } from "@locksmith-hq/input";
import { PageHeader } from "@locksmith-hq/page-header";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Route, Routes, useParams } from "react-router";
import type { Client, Environment, Project } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

/** Row actions: rename and delete (with confirm). Shared by projects and environments. */
function RowActions({
  name,
  onRename,
  onDelete,
}: {
  name: string;
  onRename: (n: string) => Promise<unknown>;
  onDelete: () => Promise<unknown>;
}) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [value, setValue] = useState(name);
  if (editing) {
    return (
      <form
        className="flex flex-wrap items-center gap-2 [&_[data-slot=input]]:w-60"
        onSubmit={(e) => {
          e.preventDefault();
          void onRename(value).then(
            () => setEditing(false),
            () => {},
          );
        }}
      >
        <Input aria-label={`New name for ${name}`} value={value} onChange={(e) => setValue(e.target.value)} />
        <Button size="sm" type="submit">
          Save
        </Button>
        <Button variant="ghost" size="sm" type="button" onClick={() => setEditing(false)}>
          Cancel
        </Button>
      </form>
    );
  }
  if (confirming) {
    return (
      <span
        role="alertdialog"
        className="flex flex-wrap items-center gap-2 [&_[data-slot=input]]:w-60"
        aria-label={`Delete ${name}?`}
      >
        Delete {name}?
        <Button
          variant="destructive"
          size="sm"
          onClick={() =>
            void onDelete().then(
              () => setConfirming(false),
              () => setConfirming(false),
            )
          }
        >
          Confirm delete
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>
          Cancel
        </Button>
      </span>
    );
  }
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
        Rename {name}
      </Button>
      <Button variant="ghost" size="sm" className="text-(--destructive-text)" onClick={() => setConfirming(true)}>
        Delete {name}
      </Button>
    </>
  );
}

function CreateForm({ label, onCreate }: { label: string; onCreate: (name: string) => Promise<unknown> }) {
  const [name, setName] = useState("");
  return (
    <form
      className="mb-4 flex flex-wrap items-center gap-2 [&_[data-slot=input]]:w-60"
      onSubmit={(e) => {
        e.preventDefault();
        void onCreate(name).then(
          () => setName(""),
          () => {},
        );
      }}
    >
      <Input aria-label={`${label} name`} value={name} onChange={(e) => setName(e.target.value)} required />
      <Button type="submit">Create {label}</Button>
    </form>
  );
}

function ProjectList({ client }: { client: Client }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["projects"], queryFn: () => client.listProjects() });
  const done = () => qc.invalidateQueries({ queryKey: ["projects"] });
  const create = useMutation({ mutationFn: (name: string) => client.createProject({ name }), onSuccess: done });
  const rename = useMutation({
    mutationFn: (v: { id: string; name: string }) => client.updateProject(v.id, { name: v.name }),
    onSuccess: done,
  });
  const del = useMutation({ mutationFn: (id: string) => client.deleteProject(id), onSuccess: done });
  const err = create.error ?? rename.error ?? del.error;
  return (
    <>
      <PageHeader title="Projects" />
      {err && (
        <Alert variant="destructive">
          <AlertDescription>{errMsg(err)}</AlertDescription>
        </Alert>
      )}
      <CreateForm label="project" onCreate={(n) => create.mutateAsync(n)} />
      <QueryState query={q} empty="No projects yet.">
        {(items: Project[]) => (
          <ul className="divide-y rounded-md border bg-card">
            {items.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <Link className="mr-auto font-medium underline-offset-3 hover:underline" to={`/projects/${p.id}`}>
                  {p.name}
                </Link>
                <RowActions
                  name={p.name}
                  onRename={(name) => rename.mutateAsync({ id: p.id, name })}
                  onDelete={() => del.mutateAsync(p.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </>
  );
}

function ProjectDetail({ client }: { client: Client }) {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["environments", id], queryFn: () => client.listEnvironments(id) });
  const done = () => qc.invalidateQueries({ queryKey: ["environments", id] });
  const create = useMutation({ mutationFn: (name: string) => client.createEnvironment(id, { name }), onSuccess: done });
  const rename = useMutation({
    mutationFn: (v: { env: string; name: string }) => client.updateEnvironment(id, v.env, { name: v.name }),
    onSuccess: done,
  });
  const del = useMutation({ mutationFn: (env: string) => client.deleteEnvironment(id, env), onSuccess: done });
  const err = create.error ?? rename.error ?? del.error;
  return (
    <>
      <PageHeader title="Environments" />
      <Breadcrumb className="mb-3">
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <Link to="/projects">All projects</Link>
            </BreadcrumbLink>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      {err && (
        <Alert variant="destructive">
          <AlertDescription>{errMsg(err)}</AlertDescription>
        </Alert>
      )}
      <CreateForm label="environment" onCreate={(n) => create.mutateAsync(n)} />
      <QueryState query={q} empty="No environments yet.">
        {(items: Environment[]) => (
          <ul className="divide-y rounded-md border bg-card">
            {items.map((e) => (
              <li key={e.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <span className="mr-auto font-medium">{e.name}</span>
                <RowActions
                  name={e.name}
                  onRename={(name) => rename.mutateAsync({ env: e.id, name })}
                  onDelete={() => del.mutateAsync(e.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </>
  );
}

export function Projects({ client }: { client: Client }) {
  return (
    <Routes>
      <Route index element={<ProjectList client={client} />} />
      <Route path=":id" element={<ProjectDetail client={client} />} />
    </Routes>
  );
}
