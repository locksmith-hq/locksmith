import { NavLink, Navigate, Route, Routes } from "react-router";
import { Logo } from "@locksmith/ui";
import type { Client } from "@locksmith/control-plane-client";
import { Agents, Audit } from "./App";
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
  return (
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
          <Route path="overview" element={<EmptyPage title="Overview" />} />
          <Route path="projects/*" element={<EmptyPage title="Projects" />} />
          <Route path="secrets/*" element={<EmptyPage title="Secrets" />} />
          <Route path="agents" element={<Agents client={client} />} />
          <Route path="grants" element={<EmptyPage title="Grants" />} />
          <Route path="activity" element={<Audit client={client} />} />
          <Route path="*" element={<EmptyPage title="Not found" />} />
        </Routes>
      </main>
    </div>
  );
}
