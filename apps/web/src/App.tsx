import { useEffect, useMemo, useState } from "react";
import { BrowserRouter, MemoryRouter } from "react-router";
import { Shell } from "./Shell";
import { createClient, type Client } from "@locksmith/control-plane-client";
import { withUnauthorizedHandler } from "./api/client";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Button } from "@locksmith-hq/ui/button";
import { Card } from "@locksmith-hq/ui/card";
import { Loader } from "@locksmith-hq/ui/loader";
import { Mark } from "@locksmith-hq/ui/mark";
import { Wordmark } from "@locksmith-hq/ui/wordmark";
import { createAuth, defaultConfig, type AuthService, type AuthState, type Provider } from "./auth";

let defaultAuth: AuthService | undefined;
const getDefaultAuth = () => (defaultAuth ??= createAuth(defaultConfig()));

// `client` (tests, embedding) bypasses sign-in; otherwise the console is gated on an OIDC session.
// `initialPath` (tests) swaps the browser history for an in-memory one.
export function App({ client, auth, initialPath }: { client?: Client; auth?: AuthService; initialPath?: string }) {
  const body = client ? <Shell client={client} /> : <AuthGate auth={auth ?? getDefaultAuth()} />;
  return initialPath ? (
    <MemoryRouter initialEntries={[initialPath]}>{body}</MemoryRouter>
  ) : (
    <BrowserRouter>{body}</BrowserRouter>
  );
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
  const client = useMemo(
    () =>
      withUnauthorizedHandler(
        createClient("", "", () => auth.token()),
        () => void auth.signOut(),
      ),
    [auth],
  );

  if (state.status === "loading") return <Loader fill label="Signing in" />;
  if (state.status === "signed-out") return <SignIn auth={auth} notice={state.notice} />;
  return (
    <Shell
      client={client}
      user={state.user.email ?? state.user.name ?? "Signed in"}
      onSignOut={() => void auth.signOut()}
    />
  );
}

const CHOICES: Record<Provider, string> = {
  github: "Continue with GitHub",
  google: "Continue with Google",
  email: "Continue with email",
};

// Google's four-colour "G" (brand colours are fixed, so they do not follow the theme tokens).
const GoogleG = () => (
  <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
    <path
      fill="#EA4335"
      d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.8 2.4 30.3 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z"
    />
    <path
      fill="#4285F4"
      d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.6 5.9c4.4-4.1 7-10.1 7-17.6z"
    />
    <path fill="#FBBC05" d="M10.5 28.7a14.5 14.5 0 0 1 0-9.4l-7.9-6.1a24 24 0 0 0 0 21.6l7.9-6.1z" />
    <path
      fill="#34A853"
      d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.6-5.9c-2.1 1.4-4.9 2.3-8.3 2.3-6.3 0-11.6-4.1-13.5-9.8l-7.9 6.1C6.5 42.6 14.6 48 24 48z"
    />
  </svg>
);
// GitHub's mark (the Octicons "mark-github" path). It takes the button's text colour, as GitHub's logo rules ask.
const GitHubMark = () => (
  <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
  </svg>
);
const MailIcon = () => (
  <svg
    width="18"
    height="18"
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <rect x="2" y="3.5" width="12" height="9" rx="1.75" />
    <path d="M2.5 5l5.5 4 5.5-4" />
  </svg>
);
const ICONS: Record<Provider, React.ReactNode> = { github: <GitHubMark />, google: <GoogleG />, email: <MailIcon /> };

function SignIn({ auth, notice }: { auth: AuthService; notice?: string }) {
  const providers = auth.providers ?? ["github", "google", "email"];
  return (
    <main className="grid min-h-screen place-items-center p-6">
      <Card className="w-full max-w-sm items-center gap-4 px-7 pt-9 pb-6 text-center">
        <Mark size={72} />
        <h1>
          <Wordmark size={22} />
        </h1>
        <p className="text-[15px] leading-[22px] text-muted-foreground">
          Your agents use credentials without ever holding them.
        </p>
        {notice && (
          <Alert variant="destructive">
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        )}
        <section aria-label="Sign in" className="flex w-full flex-col gap-2.5">
          {providers.map((p, i) => (
            <Button
              key={p}
              variant={i === 0 ? "default" : "outline"}
              size="lg"
              className="w-full"
              onClick={() => void auth.signIn(p)}
            >
              {ICONS[p]}
              {CHOICES[p]}
            </Button>
          ))}
        </section>
        <p className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
          <Mark small mono size={14} /> Access is invite-only.
        </p>
      </Card>
    </main>
  );
}
