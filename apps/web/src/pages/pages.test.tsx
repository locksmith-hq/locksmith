import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "@locksmith/control-plane-client";
import { App } from "../App";
import { installFixtureFetch } from "../api/fixtures";

afterEach(() => { vi.unstubAllGlobals(); localStorage.clear(); });
const open = (path: string, opts?: Parameters<typeof installFixtureFetch>[0]) => {
  const fx = installFixtureFetch(opts);
  render(<App client={createClient("o")} initialPath={path} />);
  return fx;
};

test("overview shows counts, recent activity empty state and a dismissible checklist", async () => {
  open("/overview");
  expect(await screen.findByTestId("count-projects")).toHaveTextContent("Projects: 1");
  expect(await screen.findByText("No activity yet.")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Dismiss"));
  expect(screen.queryByRole("region", { name: "Get started" })).toBeNull();
  expect(localStorage.getItem("ls-get-started-dismissed")).toBe("1");
});

test("projects: create, rename, delete with confirm", async () => {
  const fx = open("/projects");
  expect(await screen.findByText("payments")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("project name"), "billing");
  await userEvent.click(screen.getByText("Create project"));
  expect(await screen.findByText("billing")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Rename billing"));
  const input = screen.getByLabelText("New name for billing");
  await userEvent.clear(input); await userEvent.type(input, "invoices");
  await userEvent.click(screen.getByText("Save"));
  expect(await screen.findByText("invoices")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Delete invoices"));
  expect(fx.requests.some((r) => r.startsWith("DELETE"))).toBe(false);
  await userEvent.click(screen.getByText("Confirm delete"));
  await waitFor(() => expect(screen.queryByText("invoices")).toBeNull());
});

test("projects: 409 on duplicate name is shown; shown", async () => {
  open("/projects");
  await screen.findByText("payments");
  await userEvent.type(screen.getByLabelText("project name"), "payments");
  await userEvent.click(screen.getByText("Create project"));
  expect(await screen.findByRole("alert")).toBeInTheDocument();
});

test("projects: 403 list shows an error with retry, not the empty message", async () => {
  open("/projects", { fail: { "GET /v1/projects": 403 } });
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.getByText("Retry")).toBeInTheDocument();
  expect(screen.queryByText("No projects yet.")).toBeNull();
});

test("projects: empty", async () => {
  open("/projects", { empty: true });
  expect(await screen.findByText("No projects yet.")).toBeInTheDocument();
});

test("environments: list, create, delete inside a project", async () => {
  open("/projects/00000000-0000-4000-8000-000000000001");
  expect(await screen.findByText("dev")).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("environment name"), "prod");
  await userEvent.click(screen.getByText("Create environment"));
  expect(await screen.findByText("prod")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Delete prod"));
  await userEvent.click(screen.getByText("Confirm delete"));
  await waitFor(() => expect(screen.queryByText("prod")).toBeNull());
});
