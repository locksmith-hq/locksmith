import { NavLink, Navigate, Route, Routes, useLocation } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Logo } from "@locksmith/ui";
import type { Client } from "@locksmith/control-plane-client";
import { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Agents } from "./pages/Agents";
import { WorkloadIdentities } from "./pages/WorkloadIdentities";
import { GrantsPage } from "./pages/Grants";
import { Activity } from "./pages/Activity";
import { Secrets } from "./pages/Secrets";
import { Overview } from "./pages/Overview";
import { Projects } from "./pages/Projects";
import { McpTools } from "./pages/McpTools";
import { McpClients } from "./pages/McpClients";
import { Bindings } from "./pages/Bindings";
import { mockBindingsClient, type BindingsClient } from "./api/bindings";
import { EmptyPage } from "./pages/EmptyPage";
import "./shell.css";

const NAV: ReadonlyArray<{ heading?: string; items: ReadonlyArray<readonly [path: string, label: string]> }> = [
  { items: [["overview", "Home"]] },
  { heading: "Secret Management", items: [["projects", "Projects"], ["environments", "Environments"], ["secrets", "Secrets"]] },
  { heading: "Agent Gateway", items: [["agents", "Agents"], ["workload-identities", "Workload identities"], ["grants", "Grants"], ["bindings", "Bindings"]] },
  { heading: "MCP", items: [["tools", "Tools"], ["clients", "Clients"]] },
  { items: [["activity", "Activity"]] },
];

/** Environments live inside a project: open the project being viewed, else the first one. */
function EnvironmentsRedirect({ client, selected }: { client: Client; selected?: string }) {
  const q = useQuery({ queryKey: ["projects"], queryFn: () => client.listProjects() });
  if (selected) return <Navigate to={`/projects/${selected}`} replace />;
  if (q.isPending) return <EmptyPage title="Environments" note="Loading…" />;
  const first = q.data?.[0];
  return <Navigate to={first ? `/projects/${first.id}` : "/projects"} replace />;
}

/** Org switcher (top right). Single org until a workspace API lists the user's orgs (T3 progress.md). */
function OrgSwitcher({ name }: { name: string }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    const away = (e: MouseEvent) => { if (!(e.target as Element).closest(".shell-org")) setOpen(false); };
    document.addEventListener("keydown", esc); document.addEventListener("mousedown", away);
    return () => { document.removeEventListener("keydown", esc); document.removeEventListener("mousedown", away); };
  }, [open]);
  return (
    <div className="shell-org" aria-label="Organization">
      <button aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>{name} ▾</button>
      {open && <ul role="menu"><li role="menuitem" aria-current="true">{name}</li></ul>}
    </div>
  );
}

/** Signed-in frame: sidebar, org header and sign-out around the routed pages. */
export function Shell({ client, bindings = mockBindingsClient, user, onSignOut }: { client: Client; bindings?: BindingsClient; user?: string; onSignOut?: () => void }) {
  const [selected, setSelected] = useState<string | undefined>();
  const { pathname } = useLocation();
  const m = /^\/projects\/([^/]+)/.exec(pathname);
  useEffect(() => { if (m) setSelected(m[1]); }, [m?.[1]]);
  const [queryClient] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }));
  return (
    <QueryClientProvider client={queryClient}>
    <div className="shell">
      <aside className="shell-side">
        <div className="shell-brand"><Logo size={28} /> Locksmith</div>
        <nav aria-label="Pages">
          {NAV.map((g, i) => (
            <div key={i} className="shell-group">
              {g.heading && <p className="shell-nav-h">{g.heading}</p>}
              {g.items.map(([path, label]) => <NavLink key={path} to={`/${path}`}>{label}</NavLink>)}
            </div>
          ))}
        </nav>
        <div className="shell-user">
          {user ? <span data-testid="signed-in-as">{user}</span> : <span>Signed in</span>}
          {onSignOut && <button className="shell-signout" onClick={onSignOut}>Sign out</button>}
        </div>
      </aside>
      <main className="shell-main">
        <header className="shell-top"><OrgSwitcher name="Locksmith" /></header>
        <Routes>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Overview client={client} />} />
          <Route path="projects/*" element={<Projects client={client} />} />
          <Route path="secrets/*" element={<Secrets client={client} />} />
          <Route path="environments" element={<EnvironmentsRedirect client={client} selected={selected} />} />
          <Route path="agents" element={<Agents client={client} />} />
          <Route path="workload-identities" element={<WorkloadIdentities client={client} />} />
          <Route path="grants" element={<GrantsPage client={client} />} />
          <Route path="bindings" element={<Bindings client={bindings} />} />
          <Route path="tools" element={<McpTools client={client} />} />
          <Route path="clients" element={<McpClients client={client} />} />
          <Route path="activity" element={<Activity client={client} />} />
          <Route path="*" element={<EmptyPage title="Not found" />} />
        </Routes>
      </main>
    </div>
    </QueryClientProvider>
  );
}
