import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { expect, test, vi } from "vitest";
import { QueryState } from "./QueryState";

const idle = { data: undefined, isPending: false, isError: false, error: null, refetch: vi.fn() };

test("loading shows a status and no empty message", () => {
  render(
    <QueryState query={{ ...idle, isPending: true }} empty="No projects yet.">
      {() => null}
    </QueryState>,
  );
  expect(screen.getByRole("status")).toHaveTextContent("Loading");
  expect(screen.queryByText("No projects yet.")).toBeNull();
});

test("empty shows the empty message", () => {
  render(
    <QueryState query={{ ...idle, data: [] }} empty="No projects yet.">
      {() => <p>rows</p>}
    </QueryState>,
  );
  expect(screen.getByText("No projects yet.")).toBeInTheDocument();
  expect(screen.queryByText("rows")).toBeNull();
});

test("data renders the children", () => {
  render(<QueryState query={{ ...idle, data: ["a", "b"] }}>{(d) => <p>{d.join(",")}</p>}</QueryState>);
  expect(screen.getByText("a,b")).toBeInTheDocument();
});

test("error shows the message and a retry, never the empty state", async () => {
  const refetch = vi.fn();
  render(
    <QueryState query={{ ...idle, isError: true, error: new Error("boom"), refetch }} empty="No projects yet.">
      {() => null}
    </QueryState>,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("boom");
  expect(screen.queryByText("No projects yet.")).toBeNull();
  await userEvent.click(screen.getByText("Retry"));
  expect(refetch).toHaveBeenCalledOnce();
});

test("works with a real useQuery: fails with a 5xx, then retry succeeds", async () => {
  let ok = false;
  const load = vi.fn(async () => {
    if (!ok) throw new Error("server error");
    return ["x"];
  });
  function Page() {
    const q = useQuery({ queryKey: ["t"], queryFn: load, retry: false });
    return <QueryState query={q}>{(d) => <p>{d[0]}</p>}</QueryState>;
  }
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Page />
    </QueryClientProvider>,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent("server error");
  ok = true;
  await userEvent.click(screen.getByText("Retry"));
  expect(await screen.findByText("x")).toBeInTheDocument();
});
