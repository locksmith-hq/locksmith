import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "@locksmith/control-plane-client";
import { App } from "../App";
import { installFixtureFetch } from "../api/fixtures";

afterEach(() => vi.unstubAllGlobals());

const P = "00000000-0000-4000-8000-000000000001";
const E = "00000000-0000-4000-8000-000000000010";
const PATH = `/projects/${P}/environments/${E}/honey-tokens`;
const open = (opts?: Parameters<typeof installFixtureFetch>[0]) => {
  const fx = installFixtureFetch(opts);
  const view = render(<App client={createClient("o")} initialPath={PATH} />);
  return { fx, ...view };
};

test("honey tokens: lists name, template, last trigger or never, and state", async () => {
  open();
  expect(await screen.findByText("prod-aws-decoy")).toBeInTheDocument();
  expect(within(screen.getByRole("table")).getByText("AWS access key")).toBeInTheDocument();
  expect(screen.getByText("2026-11-19T02:15:00Z")).toBeInTheDocument();
  expect(screen.getByText("never")).toBeInTheDocument();
  expect(screen.getAllByText("Active")).toHaveLength(2);
});

test("honey tokens: create from a template", async () => {
  const { fx } = open();
  await screen.findByText("prod-aws-decoy");
  await userEvent.type(screen.getByLabelText("Honey token name"), "stripe-decoy");
  await userEvent.selectOptions(screen.getByLabelText("Honey token template"), "slack_token");
  await userEvent.click(screen.getByText("Create honey token"));
  expect(await screen.findByText("stripe-decoy")).toBeInTheDocument();
  expect(within(screen.getByRole("table")).getByText("Slack token")).toBeInTheDocument();
  expect(fx.requests.filter((r) => r.startsWith("POST") && r.endsWith("/honey-tokens"))).toHaveLength(1);
});

test("honey tokens: disable marks the row disabled", async () => {
  const { fx } = open();
  await userEvent.click(await screen.findByText("Disable ci-github-decoy"));
  expect(await screen.findByText("Disabled")).toBeInTheDocument();
  expect(screen.getByText("Disable ci-github-decoy")).toBeDisabled();
  expect(fx.requests.some((r) => r.endsWith("/disable"))).toBe(true);
});

test("honey tokens: delete asks for confirmation first", async () => {
  const { fx } = open();
  await userEvent.click(await screen.findByText("Delete ci-github-decoy"));
  expect(fx.requests.some((r) => r.startsWith("DELETE"))).toBe(false);
  await userEvent.click(screen.getByText("Confirm delete"));
  await waitFor(() => expect(screen.queryByText("ci-github-decoy")).toBeNull());
  expect(fx.requests.some((r) => r.startsWith("DELETE"))).toBe(true);
});

test("honey tokens: copy puts only the plant command on the clipboard", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
  open();
  await screen.findByText("prod-aws-decoy");
  fireEvent.click(screen.getByText("Copy plant command: prod-aws-decoy"));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith("smith honey plant prod-aws-decoy --into .env"));
});

test("honey tokens: a 403 shows an owner-only message and no controls", async () => {
  open({ fail: { [`GET /v1/projects/${P}/environments/${E}/honey-tokens`]: 403 } });
  expect(await screen.findByText(/Only an organization owner/)).toBeInTheDocument();
  expect(screen.queryByText("Create honey token")).toBeNull();
});

test("honey tokens: no value is rendered (the page shows explicit metadata fields only)", async () => {
  open();
  await screen.findByText("prod-aws-decoy");
  expect(screen.getByRole("region", { name: "Honey tokens" }).textContent).not.toMatch(
    /AKIA|ghp_|xox[bp]-|value|secret/i,
  );
});

test("honey tokens: reachable from each environment of a project", async () => {
  installFixtureFetch();
  render(<App client={createClient("o")} initialPath={`/projects/${P}`} />);
  expect(await screen.findByText("Honey tokens: dev")).toHaveAttribute("href", PATH);
});
