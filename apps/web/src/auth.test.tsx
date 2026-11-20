import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import { createAuth, safeReturnTo, type AuthService } from "./auth";

const ISS = "http://localhost:8180/realms/locksmith";
const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const jwt = (claims: object) => `${b64({ alg: "none" })}.${b64(claims)}.sig`;
const TOKEN = "ACCESSTOKEN-SENTINEL";
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

let nav: string[];
let fetchMock: ReturnType<typeof vi.fn>;
let signInStatus: number;

const mk = () =>
  createAuth({ issuer: ISS, clientId: "locksmith-web", redirectUri: "http://localhost:3000/", navigate: (u) => nav.push(u) });

beforeEach(() => {
  nav = [];
  signInStatus = 204;
  sessionStorage.clear(); localStorage.clear();
  window.history.replaceState(null, "", "/");
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === `${ISS}/protocol/openid-connect/token`) {
      const now = Math.floor(Date.now() / 1000);
      return json({
        access_token: TOKEN, token_type: "Bearer", expires_in: 300, scope: "openid email profile",
        id_token: jwt({ iss: ISS, aud: "locksmith-web", sub: "u1", exp: now + 300, iat: now, email: "ada@example.com" }),
      });
    }
    if (url === "/v1/auth/sign-in" && init?.method === "POST") return new Response(null, { status: signInStatus });
    if (url === "/v1/auth/sign-out" && init?.method === "POST") return new Response(null, { status: 204 });
    if (url.startsWith("/v1/")) return json({ items: [] });
    return json({}, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

/** Starts a sign-in, then simulates the issuer redirecting back with a code. */
async function roundTrip(auth: AuthService, provider: "github" | "google" | "email", from = "/") {
  window.history.replaceState(null, "", from);
  await auth.signIn(provider);
  const url = new URL(nav.at(-1)!);
  window.history.replaceState(null, "", `/?code=abc&state=${url.searchParams.get("state")}`);
  return url;
}

test("sign-in builds a PKCE S256 authorize URL and routes GitHub and Google by kc_idp_hint", async () => {
  const gh = await roundTrip(mk(), "github");
  expect(gh.origin + gh.pathname).toBe(`${ISS}/protocol/openid-connect/auth`);
  expect(gh.searchParams.get("response_type")).toBe("code");
  expect(gh.searchParams.get("client_id")).toBe("locksmith-web");
  expect(gh.searchParams.get("code_challenge_method")).toBe("S256");
  expect(gh.searchParams.get("code_challenge")).toBeTruthy();
  expect(gh.searchParams.get("kc_idp_hint")).toBe("github");
  expect((await roundTrip(mk(), "google")).searchParams.get("kc_idp_hint")).toBe("google");
  expect((await roundTrip(mk(), "email")).searchParams.has("kc_idp_hint")).toBe(false);
});

test("callback signs in, keeps tokens out of storage and logs, and returns to the requested path", async () => {
  const log = vi.spyOn(console, "log"); const info = vi.spyOn(console, "info"); const warn = vi.spyOn(console, "warn");
  const auth = mk();
  await roundTrip(auth, "github", "/audit?x=1");
  await auth.start();
  expect(auth.getState().status).toBe("signed-in");
  expect(auth.token()).toBe(TOKEN);
  expect(window.location.pathname + window.location.search).toBe("/audit?x=1");
  const signIn = fetchMock.mock.calls.find((c) => c[0] === "/v1/auth/sign-in")!;
  expect(signIn[1].headers.authorization).toBe(`Bearer ${TOKEN}`);
  const stored = JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]);
  expect(stored).not.toContain(TOKEN);
  expect(stored).not.toContain("id_token");
  expect(JSON.stringify([log.mock.calls, info.mock.calls, warn.mock.calls])).not.toContain(TOKEN);
});

test("a rejected sign-in call leaves the user signed out", async () => {
  signInStatus = 403;
  const auth = mk();
  await roundTrip(auth, "email");
  await auth.start();
  expect(auth.getState()).toEqual({ status: "signed-out", notice: "Verify your email address, then sign in again." });
  expect(auth.token()).toBeUndefined();
});

test("a failed token exchange shows a notice and cleans the URL", async () => {
  const auth = mk();
  await roundTrip(auth, "github");
  fetchMock.mockImplementationOnce(async () => json({ error: "invalid_grant" }, 400));
  await auth.start();
  expect(auth.getState()).toMatchObject({ status: "signed-out", notice: "Sign-in failed. Try again." });
  expect(window.location.search).toBe("");
});

test("start without a callback is signed out", async () => {
  const auth = mk();
  await auth.start();
  expect(auth.getState()).toEqual({ status: "signed-out" });
});

test("return-to only accepts same-origin paths", () => {
  expect(safeReturnTo("/audit?a=1#h")).toBe("/audit?a=1#h");
  for (const bad of ["https://evil.test/", "//evil.test", "/\\evil.test", "javascript:alert(1)", "", undefined, 5]) {
    expect(safeReturnTo(bad)).toBe("/");
  }
});

test("sign-out records the marker, clears the token and goes to the issuer logout", async () => {
  const auth = mk();
  await roundTrip(auth, "github");
  await auth.start();
  await auth.signOut();
  expect(auth.token()).toBeUndefined();
  expect(auth.getState().status).toBe("signed-out");
  const out = fetchMock.mock.calls.find((c) => c[0] === "/v1/auth/sign-out")!;
  expect(out[1].headers.authorization).toBe(`Bearer ${TOKEN}`);
  const url = new URL(nav.at(-1)!);
  expect(url.pathname).toBe("/realms/locksmith/protocol/openid-connect/logout");
  expect(url.searchParams.get("id_token_hint")).toBeTruthy();
});

test("an expired access token is not sent", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    const auth = mk();
    await roundTrip(auth, "github");
    await auth.start();
    expect(auth.token()).toBe(TOKEN);
    vi.setSystemTime(Date.now() + 400_000);
    expect(auth.token()).toBeUndefined();
  } finally { vi.useRealTimers(); }
});

test("UI: signed-out shows the three choices; signed-in shows the user, bearer requests and sign out", async () => {
  const auth = mk();
  render(<App auth={auth} />);
  expect(await screen.findByText("Continue with GitHub")).toBeInTheDocument();
  expect(screen.getByText("Continue with Google")).toBeInTheDocument();
  await userEvent.click(screen.getByText("Continue with email"));
  await waitFor(() => expect(nav).toHaveLength(1));
  expect(new URL(nav[0]!).searchParams.has("kc_idp_hint")).toBe(false);

  await roundTrip(auth, "github");
  await auth.start();
  expect(await screen.findByTestId("signed-in-as")).toHaveTextContent("ada@example.com");
  await waitFor(() => expect(fetchMock.mock.calls.some((c) => c[0] === "/v1/agents")).toBe(true));
  const call = fetchMock.mock.calls.find((c) => c[0] === "/v1/agents")!;
  expect(call[1].headers.authorization).toBe(`Bearer ${TOKEN}`);
  expect(call[1].headers["x-locksmith-dev-org"]).toBeUndefined();
  await userEvent.click(screen.getByText("Sign out"));
  expect(await screen.findByText("Continue with GitHub")).toBeInTheDocument();
});

test("UI: an expiry event returns to the sign-in screen with a notice", async () => {
  let push: (s: unknown) => void = () => {};
  let st: unknown = { status: "signed-in", user: { accessToken: "t", email: "ada@example.com" } };
  const fake: AuthService = {
    start: async () => {}, signIn: async () => {}, signOut: async () => {}, token: () => "t",
    getState: () => st as never,
    subscribe: (fn) => { push = fn as never; return () => {}; },
  };
  render(<App auth={fake} />);
  expect(await screen.findByTestId("signed-in-as")).toBeInTheDocument();
  st = { status: "signed-out", notice: "Your session expired. Sign in again." };
  push(st);
  expect(await screen.findByRole("alert")).toHaveTextContent("Your session expired");
  expect(screen.getByText("Continue with GitHub")).toBeInTheDocument();
});
