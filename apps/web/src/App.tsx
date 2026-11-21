import { useEffect, useMemo, useState } from "react";
import { BrowserRouter, MemoryRouter } from "react-router";
import { Shell } from "./Shell";
import { createClient, type Client } from "@locksmith/control-plane-client";
import { withUnauthorizedHandler } from "./api/client";
import { createAuth, defaultConfig, type AuthService, type AuthState } from "./auth";



let defaultAuth: AuthService | undefined;
const getDefaultAuth = () => (defaultAuth ??= createAuth(defaultConfig()));

// `client` (tests, embedding) bypasses sign-in; otherwise the console is gated on an OIDC session.
// `initialPath` (tests) swaps the browser history for an in-memory one.
export function App({ client, auth, initialPath }: { client?: Client; auth?: AuthService; initialPath?: string }) {
  const body = client ? <Shell client={client} /> : <AuthGate auth={auth ?? getDefaultAuth()} />;
  return initialPath ? <MemoryRouter initialEntries={[initialPath]}>{body}</MemoryRouter> : <BrowserRouter>{body}</BrowserRouter>;
}

function AuthGate({ auth }: { auth: AuthService }) {
  const [state, setState] = useState<AuthState>(auth.getState());
  useEffect(() => {
    const off = auth.subscribe(setState);
    setState(auth.getState());
    void auth.start();
    return off;
  }, [auth]);
  // A 401 from the API means the session is gone: sign out, which returns to the sign-in screen.
  const client = useMemo(() => withUnauthorizedHandler(createClient("", "", () => auth.token()), () => void auth.signOut()), [auth]);

  if (state.status === "loading") return <main><p>Signing in…</p></main>;
  if (state.status === "signed-out") return <SignIn auth={auth} notice={state.notice} />;
  return <Shell client={client} user={state.user.email ?? state.user.name ?? "Signed in"} onSignOut={() => void auth.signOut()} />;
}

function SignIn({ auth, notice }: { auth: AuthService; notice?: string }) {
  return (
    <main>
      <h1>Locksmith</h1>
      {notice && <p role="alert">{notice}</p>}
      <section aria-label="Sign in">
        <button onClick={() => void auth.signIn("github")}>Continue with GitHub</button>
        <button onClick={() => void auth.signIn("google")}>Continue with Google</button>
        <button onClick={() => void auth.signIn("email")}>Continue with email</button>
      </section>
    </main>
  );
}
