import { useEffect, useMemo, useState } from "react";
import { BrowserRouter, MemoryRouter } from "react-router";
import { Shell } from "./Shell";
import { Loader } from "./Loader";
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

  if (state.status === "loading") return <Loader fill label="Signing in" />;
  if (state.status === "signed-out") return <SignIn auth={auth} notice={state.notice} />;
  return <Shell client={client} user={state.user.email ?? state.user.name ?? "Signed in"} onSignOut={() => void auth.signOut()} />;
}

const CHOICES: Record<Provider, string> = { github: "Continue with GitHub", google: "Continue with Google", email: "Continue with email" };

// Google's four-colour "G" (brand colours are fixed, so they do not follow the theme tokens).
const GoogleG = () => (
  <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
    <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.8 2.4 30.3 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z" />
    <path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.6 5.9c4.4-4.1 7-10.1 7-17.6z" />
    <path fill="#FBBC05" d="M10.5 28.7a14.5 14.5 0 0 1 0-9.4l-7.9-6.1a24 24 0 0 0 0 21.6l7.9-6.1z" />
    <path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.6-5.9c-2.1 1.4-4.9 2.3-8.3 2.3-6.3 0-11.6-4.1-13.5-9.8l-7.9 6.1C6.5 42.6 14.6 48 24 48z" />
  </svg>
);
const MailIcon = () => (
  <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <rect x="2" y="3.5" width="12" height="9" rx="1.75" /><path d="M2.5 5l5.5 4 5.5-4" />
  </svg>
);
const ICONS: Partial<Record<Provider, React.ReactNode>> = { google: <GoogleG />, email: <MailIcon /> };

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
            <button key={p} className={i === 0 ? "btn primary" : "btn"} onClick={() => void auth.signIn(p)}>{ICONS[p]}{CHOICES[p]}</button>
          ))}
        </section>
        <p className="login-foot"><Logo size={14} /> Access is invite-only.</p>
      </div>
    </main>
  );
}
