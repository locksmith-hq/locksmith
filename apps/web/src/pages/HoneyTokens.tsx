import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { Head } from "@locksmith/ui";
import {
  ApiError,
  HONEY_TEMPLATES,
  type Client,
  type HoneyTemplate,
  type HoneyToken,
} from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

const TEMPLATE_LABEL: Record<HoneyTemplate, string> = {
  aws_access_key: "AWS access key",
  github_pat: "GitHub token",
  slack_token: "Slack token",
  generic_api_key: "Generic API key",
};

/** The command to plant a decoy. A literal placeholder path: it carries a name, never a value. */
const plantCommand = (name: string) => `smith honey plant ${name} --into .env`;

function Row({ t, onDisable, onDelete }: { t: HoneyToken; onDisable: () => void; onDelete: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(plantCommand(t.name));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <tr>
      <td>{t.name}</td>
      <td>{TEMPLATE_LABEL[t.template]}</td>
      <td>
        <time dateTime={t.created_at}>{t.created_at}</time>
      </td>
      <td>{t.last_triggered_at ? <time dateTime={t.last_triggered_at}>{t.last_triggered_at}</time> : "never"}</td>
      <td>{t.disabled_at ? "Disabled" : "Active"}</td>
      <td>
        <button className="btn sm" onClick={() => void copy()}>
          Copy plant command: {t.name}
        </button>
        {copied && <span role="status"> Copied</span>}{" "}
        <button className="btn sm" disabled={t.disabled_at !== null} onClick={onDisable}>
          Disable {t.name}
        </button>{" "}
        {confirming ? (
          <span role="alertdialog" className="inline-form" aria-label={`Delete ${t.name}?`}>
            Delete {t.name}?
            <button
              className="btn sm danger"
              onClick={() => {
                setConfirming(false);
                onDelete();
              }}
            >
              Confirm delete
            </button>
            <button className="btn sm quiet" onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </span>
        ) : (
          <button className="btn sm quiet danger-text" onClick={() => setConfirming(true)}>
            Delete {t.name}
          </button>
        )}
      </td>
    </tr>
  );
}

/** Honey tokens of one environment. Owner only; shows metadata, never a decoy value. */
export function HoneyTokens({ client }: { client: Client }) {
  const { id: projectId = "", envId = "" } = useParams();
  const qc = useQueryClient();
  const key = ["honey-tokens", projectId, envId];
  const q = useQuery({ queryKey: key, queryFn: () => client.listHoneyTokens(projectId, envId) });
  const done = () => qc.invalidateQueries({ queryKey: key });
  const create = useMutation({
    mutationFn: (v: { name: string; template: HoneyTemplate }) => client.createHoneyToken(projectId, envId, v),
    onSuccess: done,
  });
  const disable = useMutation({
    mutationFn: (id: string) => client.disableHoneyToken(projectId, envId, id),
    onSuccess: done,
  });
  const del = useMutation({
    mutationFn: (id: string) => client.deleteHoneyToken(projectId, envId, id),
    onSuccess: done,
  });
  const [name, setName] = useState("");
  const [template, setTemplate] = useState<HoneyTemplate>(HONEY_TEMPLATES[0]!);
  const crumbs = (
    <nav className="crumbs">
      <Link to={`/projects/${projectId}`}>Environments</Link>
    </nav>
  );
  if (q.error instanceof ApiError && q.error.status === 403)
    return (
      <section aria-label="Honey tokens">
        <Head title="Honey tokens" />
        {crumbs}
        <p>Only an organization owner can manage honey tokens.</p>
      </section>
    );
  const err = create.error ?? disable.error ?? del.error;
  return (
    <section aria-label="Honey tokens">
      <Head title="Honey tokens" />
      {crumbs}
      {err != null && (
        <p role="alert" className="state">
          {errMsg(err)}
        </p>
      )}
      <form
        className="panel form inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate({ name, template }, { onSuccess: () => setName("") });
        }}
      >
        <input aria-label="Honey token name" value={name} onChange={(e) => setName(e.target.value)} required />
        <select
          aria-label="Honey token template"
          value={template}
          onChange={(e) => setTemplate(e.target.value as HoneyTemplate)}
        >
          {HONEY_TEMPLATES.map((t) => (
            <option key={t} value={t}>
              {TEMPLATE_LABEL[t]}
            </option>
          ))}
        </select>
        <button type="submit" className="btn primary">
          Create honey token
        </button>
      </form>
      <QueryState query={q} isEmpty={(d) => d.items.length === 0} empty="No honey tokens yet.">
        {(d) => (
          <table className="grid" aria-label="Honey tokens list">
            <thead>
              <tr>
                <th>Name</th>
                <th>Template</th>
                <th>Created</th>
                <th>Last triggered</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {d.items.map((t) => (
                <Row key={t.id} t={t} onDisable={() => disable.mutate(t.id)} onDelete={() => del.mutate(t.id)} />
              ))}
            </tbody>
          </table>
        )}
      </QueryState>
    </section>
  );
}
