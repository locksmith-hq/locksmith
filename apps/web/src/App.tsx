import { useEffect, useMemo, useState } from "react";
import { BrowserRouter, MemoryRouter } from "react-router";
import { Shell } from "./Shell";
import { createClient, type Client } from "@locksmith/control-plane-client";
import { withUnauthorizedHandler } from "./api/client";
import { Logo, VaultMark } from "@locksmith/ui";
import { createAuth, defaultConfig, type AuthService, type AuthState, type Provider } from "./auth";

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

const CHOICES: Record<Provider, string> = { github: "Continue with GitHub", google: "Continue with Google", email: "Continue with email" };

function SignIn({ auth, notice }: { auth: AuthService; notice?: string }) {
  const providers = auth.providers ?? ["github", "google", "email"];
  return (
    <main className="login">
      <div className="login-card">
        <VaultMark size={72} />
        <h1 className="login-title"><span className="wordmark">locksmith</span></h1>
        <p className="login-tag">Your agents use credentials without ever holding them.</p>
        {notice && <p role="alert" className="login-notice">{notice}</p>}
        <section aria-label="Sign in" className="login-choices">
          {providers.map((p, i) => (
            <button key={p} className={i === 0 ? "btn primary" : "btn"} onClick={() => void auth.signIn(p)}>{CHOICES[p]}</button>
          ))}
        </section>
        <p className="login-foot"><Logo size={14} /> Access is invite-only.</p>
      </div>
    </main>
  );
}
