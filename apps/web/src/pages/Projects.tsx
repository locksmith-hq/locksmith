import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Route, Routes, useParams } from "react-router";
import { Head } from "@locksmith/ui";
import type { Client, Environment, Project } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";
import { HoneyTokens } from "./HoneyTokens";

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
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          void onRename(value).then(
            () => setEditing(false),
            () => {},
          );
        }}
      >
        <input aria-label={`New name for ${name}`} value={value} onChange={(e) => setValue(e.target.value)} />
        <button type="submit" className="btn sm primary">
          Save
        </button>
        <button type="button" className="btn sm quiet" onClick={() => setEditing(false)}>
          Cancel
        </button>
      </form>
    );
  }
  if (confirming) {
    return (
      <span role="alertdialog" className="inline-form" aria-label={`Delete ${name}?`}>
        Delete {name}?
        <button
          className="btn sm danger"
          onClick={() =>
            void onDelete().then(
              () => setConfirming(false),
              () => setConfirming(false),
            )
          }
        >
          Confirm delete
        </button>
        <button className="btn sm quiet" onClick={() => setConfirming(false)}>
          Cancel
        </button>
      </span>
    );
  }
  return (
    <>
      <button className="btn sm" onClick={() => setEditing(true)}>
        Rename {name}
      </button>
      <button className="btn sm quiet danger-text" onClick={() => setConfirming(true)}>
        Delete {name}
      </button>
    </>
  );
}

function CreateForm({ label, onCreate }: { label: string; onCreate: (name: string) => Promise<unknown> }) {
  const [name, setName] = useState("");
  return (
    <form
      className="panel form inline-form"
      onSubmit={(e) => {
        e.preventDefault();
        void onCreate(name).then(
          () => setName(""),
          () => {},
        );
      }}
    >
      <input aria-label={`${label} name`} value={name} onChange={(e) => setName(e.target.value)} required />
      <button type="submit" className="btn primary">
        Create {label}
      </button>
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
      <Head title="Projects" />
      {err && (
        <p role="alert" className="state">
          {errMsg(err)}
        </p>
      )}
      <CreateForm label="project" onCreate={(n) => create.mutateAsync(n)} />
      <QueryState query={q} empty="No projects yet.">
        {(items: Project[]) => (
          <ul className="list">
            {items.map((p) => (
              <li key={p.id} className="row">
                <Link to={`/projects/${p.id}`}>{p.name}</Link>
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
      <Head title="Environments" />
      <nav className="crumbs">
        <Link to="/projects">All projects</Link>
      </nav>
      {err && (
        <p role="alert" className="state">
          {errMsg(err)}
        </p>
      )}
      <CreateForm label="environment" onCreate={(n) => create.mutateAsync(n)} />
      <QueryState query={q} empty="No environments yet.">
        {(items: Environment[]) => (
          <ul className="list">
            {items.map((e) => (
              <li key={e.id} className="row">
                {e.name} <Link to={`/projects/${id}/environments/${e.id}/honey-tokens`}>Honey tokens: {e.name}</Link>
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
      <Route path=":id/environments/:envId/honey-tokens" element={<HoneyTokens client={client} />} />
    </Routes>
  );
}
