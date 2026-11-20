import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import { installFixtureFetch } from "./api/fixtures";
import type { AuthService, AuthState } from "./auth";

const fetchMock = vi.fn();
beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ title: "Unauthorized" }), { status: 401 }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

function fakeAuth(initial: AuthState) {
  let st = initial;
  let push: (s: AuthState) => void = () => {};
  const auth: AuthService = {
    start: async () => {}, signIn: async () => {}, token: () => "t",
    signOut: vi.fn(async () => { st = { status: "signed-out" }; push(st); }),
    getState: () => st,
    subscribe: (fn) => { push = fn; return () => {}; },
  };
  return auth;
}
const signedIn: AuthState = { status: "signed-in", user: { accessToken: "t", email: "ada@example.com" } };

test("signed out: every route shows sign-in and makes no API request", async () => {
  for (const path of ["/overview", "/projects", "/activity"]) {
    window.history.pushState({}, "", path);
    const { unmount } = render(<App auth={fakeAuth({ status: "signed-out" })} />);
    expect(await screen.findByText("Continue with GitHub")).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Pages" })).toBeNull();
    unmount();
  }
  expect(fetchMock).not.toHaveBeenCalled();
});

test("signed in: opens on Overview, sidebar links route to each page", async () => {
  installFixtureFetch();
  window.history.pushState({}, "", "/");
  render(<App auth={fakeAuth(signedIn)} />);
  expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  expect(screen.getByTestId("signed-in-as")).toHaveTextContent("ada@example.com");
  for (const name of ["Projects", "Secrets", "Grants"]) {
    await userEvent.click(screen.getByRole("link", { name }));
    expect(await screen.findByRole("heading", { name })).toBeInTheDocument();
  }
});

test("expired session: a 401 from the API signs out and drops the page", async () => {
  window.history.pushState({}, "", "/agents");
  const auth = fakeAuth(signedIn);
  render(<App auth={auth} />);
  expect(await screen.findByText("Continue with GitHub")).toBeInTheDocument();
  expect(auth.signOut).toHaveBeenCalled();
  expect(screen.queryByText("No agents yet.")).toBeNull();
});

test("sign-out button signs out", async () => {
  const auth = fakeAuth(signedIn);
  window.history.pushState({}, "", "/overview");
  render(<App auth={auth} />);
  await userEvent.click(await screen.findByText("Sign out"));
  await waitFor(() => expect(auth.signOut).toHaveBeenCalled());
});
