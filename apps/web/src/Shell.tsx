import { NavLink, Navigate, Route, Routes } from "react-router";
import { Logo } from "@locksmith/ui";
import type { Client } from "@locksmith/control-plane-client";
import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Agents } from "./pages/Agents";
import { GrantsPage } from "./pages/Grants";
import { Activity } from "./pages/Activity";
import { Secrets } from "./pages/Secrets";
import { Overview } from "./pages/Overview";
import { Projects } from "./pages/Projects";
import { EmptyPage } from "./pages/EmptyPage";
import "./shell.css";

const NAV = [
  ["overview", "Overview"],
  ["projects", "Projects"],
  ["secrets", "Secrets"],
  ["agents", "Agents"],
  ["grants", "Grants"],
  ["activity", "Activity"],
] as const;

/** Signed-in frame: sidebar, org header and sign-out around the routed pages. */
export function Shell({ client, user, onSignOut }: { client: Client; user?: string; onSignOut?: () => void }) {
  const [queryClient] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }));
  return (
    <QueryClientProvider client={queryClient}>
    <div className="shell">
      <aside className="shell-side">
        <div className="shell-brand"><Logo size={28} /> Locksmith</div>
        <div className="shell-org" aria-label="Organization">
          {user ? <span data-testid="signed-in-as">{user}</span> : <span>Locksmith</span>}
        </div>
        <nav aria-label="Pages">
          {NAV.map(([path, label]) => <NavLink key={path} to={`/${path}`}>{label}</NavLink>)}
        </nav>
        {onSignOut && <button className="shell-signout" onClick={onSignOut}>Sign out</button>}
      </aside>
      <main className="shell-main">
        <Routes>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Overview client={client} />} />
          <Route path="projects/*" element={<Projects client={client} />} />
          <Route path="secrets/*" element={<Secrets client={client} />} />
          <Route path="agents" element={<Agents client={client} />} />
          <Route path="grants" element={<GrantsPage client={client} />} />
          <Route path="activity" element={<Activity client={client} />} />
          <Route path="*" element={<EmptyPage title="Not found" />} />
        </Routes>
      </main>
    </div>
    </QueryClientProvider>
  );
}
