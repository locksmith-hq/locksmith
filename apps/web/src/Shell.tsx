import { NavLink, Navigate, Route, Routes, useLocation } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronsUpDown } from "lucide-react";
import { Button } from "@locksmith-hq/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@locksmith-hq/dropdown-menu";
import { Mark } from "@locksmith-hq/mark";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@locksmith-hq/sidebar";
import { Wordmark } from "@locksmith-hq/wordmark";
import type { Client } from "@locksmith/control-plane-client";
import { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Agents } from "./pages/Agents";
import { WorkloadIdentities } from "./pages/WorkloadIdentities";
import { GrantsPage } from "./pages/Grants";
import { Bindings } from "./pages/Bindings";
import { Activity } from "./pages/Activity";
import { Secrets } from "./pages/Secrets";
import { Overview } from "./pages/Overview";
import { Projects } from "./pages/Projects";
import { McpTools } from "./pages/McpTools";
import { McpClients } from "./pages/McpClients";
import { EmptyPage } from "./pages/EmptyPage";

const NAV: ReadonlyArray<{ heading?: string; items: ReadonlyArray<readonly [path: string, label: string]> }> = [
  { items: [["overview", "Home"]] },
  {
    heading: "Secret Management",
    items: [
      ["projects", "Projects"],
      ["environments", "Environments"],
      ["secrets", "Secrets"],
    ],
  },
  {
    heading: "Agent Gateway",
    items: [
      ["agents", "Agents"],
      ["workload-identities", "Workload identities"],
      ["grants", "Grants"],
      ["bindings", "Bindings"],
    ],
  },
  {
    heading: "MCP",
    items: [
      ["tools", "Tools"],
      ["clients", "Clients"],
    ],
  },
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
  return (
    // not modal: the page behind stays clickable, and a click on it closes the menu
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          {name} <ChevronsUpDown />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem aria-current="true">{name}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Signed-in frame: sidebar, org header and sign-out around the routed pages. */
export function Shell({ client, user, onSignOut }: { client: Client; user?: string; onSignOut?: () => void }) {
  const [selected, setSelected] = useState<string | undefined>();
  const { pathname } = useLocation();
  const m = /^\/projects\/([^/]+)/.exec(pathname);
  useEffect(() => {
    if (m) setSelected(m[1]);
  }, [m?.[1]]);
  const [queryClient] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }));
  return (
    <QueryClientProvider client={queryClient}>
      <SidebarProvider>
        <Sidebar collapsible="none" className="sticky top-0 h-svh border-r">
          <SidebarHeader>
            <div className="flex items-center gap-2.5 px-2 py-1.5">
              <Mark small size={26} />
              <Wordmark />
            </div>
          </SidebarHeader>
          <SidebarContent>
            <nav aria-label="Pages">
              {NAV.map((g, i) => (
                <SidebarGroup key={i}>
                  {g.heading && <SidebarGroupLabel>{g.heading}</SidebarGroupLabel>}
                  <SidebarGroupContent>
                    <SidebarMenu>
                      {g.items.map(([path, label]) => (
                        <SidebarMenuItem key={path}>
                          <SidebarMenuButton asChild>
                            <NavLink to={`/${path}`}>{label}</NavLink>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      ))}
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>
              ))}
            </nav>
          </SidebarContent>
          <SidebarFooter>
            <div className="flex flex-col items-start gap-2 rounded-md border bg-card p-2.5 text-[13px] break-all">
              {user ? <span data-testid="signed-in-as">{user}</span> : <span>Signed in</span>}
              {onSignOut && (
                <Button variant="outline" size="sm" onClick={onSignOut}>
                  Sign out
                </Button>
              )}
            </div>
          </SidebarFooter>
        </Sidebar>
        <SidebarInset className="min-w-0 p-6">
          <header className="mb-4 flex justify-end">
            <div aria-label="Organization">
              <OrgSwitcher name="Locksmith" />
            </div>
          </header>
          <Routes>
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="overview" element={<Overview client={client} />} />
            <Route path="projects/*" element={<Projects client={client} />} />
            <Route path="secrets/*" element={<Secrets client={client} />} />
            <Route path="environments" element={<EnvironmentsRedirect client={client} selected={selected} />} />
            <Route path="agents" element={<Agents client={client} />} />
            <Route path="workload-identities" element={<WorkloadIdentities client={client} />} />
            <Route path="grants" element={<GrantsPage client={client} />} />
            <Route path="bindings" element={<Bindings client={client} />} />
            <Route path="tools" element={<McpTools client={client} />} />
            <Route path="clients" element={<McpClients client={client} />} />
            <Route path="activity" element={<Activity client={client} />} />
            <Route path="*" element={<EmptyPage title="Not found" />} />
          </Routes>
        </SidebarInset>
      </SidebarProvider>
    </QueryClientProvider>
  );
}
