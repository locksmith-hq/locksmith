// OIDC sign-in for the web console: authorization code + PKCE (design decision 4), via
// oidc-client-ts. Tokens live in memory only (decision 5): the user store is an
// InMemoryWebStorage, so a reload signs the user in again through the issuer's own session.
// Only the transient PKCE state (state id, code verifier, return-to) survives the redirect, in
// sessionStorage; it holds no token. Nothing here logs a token.
import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
  type CreateSigninRequestArgs,
  type CreateSignoutRequestArgs,
  type IWindow,
  type User,
} from "oidc-client-ts";

/** Hands the request URL to `navigate` instead of oidc-client-ts's own redirect, so tests can observe it. */
class Manager extends UserManager {
  constructor(
    settings: ConstructorParameters<typeof UserManager>[0],
    private go: (url: string) => void,
  ) {
    super(settings);
  }
  private win = (): IWindow => ({
    navigate: async (p) => {
      this.go(p.url);
      return { url: p.url };
    },
    close() {},
  });
  redirectToSignin(args: Omit<CreateSigninRequestArgs, "request_type">) {
    return this._signinStart({ request_type: "si:r", ...args }, this.win());
  }
  redirectToSignout(args: CreateSignoutRequestArgs) {
    return this._signoutStart({ request_type: "so:r", ...args }, this.win());
  }
}

export type Provider = "github" | "google" | "email";
export type AuthState =
  | { status: "loading" }
  | { status: "signed-out"; notice?: string }
  | { status: "signed-in"; user: SignedInUser };
interface SignedInUser {
  accessToken: string;
  email?: string;
  name?: string;
}

export interface AuthService {
  /** Sign-in choices this deployment offers; all three when omitted. Cognito has no GitHub provider. */
  providers?: Provider[];
  /** Handles a redirect callback if the URL carries one, then reports the state. */
  start(): Promise<void>;
  signIn(provider: Provider): Promise<void>;
  signOut(): Promise<void>;
  /** Current access token, or undefined when signed out or expired. */
  token(): string | undefined;
  getState(): AuthState;
  subscribe(fn: (s: AuthState) => void): () => void;
}

export interface AuthConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Cognito hosted-UI origin. Set, the Cognito endpoint layout is used instead of Keycloak's. */
  hostedDomain?: string;
  apiBase?: string;
  /** Page navigation; injectable for tests. */
  navigate?: (url: string) => void;
}

export function defaultConfig(): AuthConfig {
  const env = (import.meta as { env?: Record<string, string | undefined> }).env ?? {};
  return {
    issuer: env.VITE_OIDC_ISSUER ?? "http://localhost:8180/realms/locksmith",
    clientId: env.VITE_OIDC_CLIENT_ID ?? "locksmith-web",
    redirectUri: `${window.location.origin}/`,
    hostedDomain: env.VITE_OIDC_HOSTED_DOMAIN,
  };
}

/** Same-origin path only: anything else (absolute URL, `//host`, `/\host`) falls back to `/`. */
export function safeReturnTo(v: unknown): string {
  return typeof v === "string" && /^\/(?![/\\])/.test(v) && !/[\r\n]/.test(v) ? v : "/";
}

const IDP_HINTS: Partial<Record<Provider, string>> = { github: "github", google: "google" };
const COGNITO_IDPS: Partial<Record<Provider, string>> = { google: "Google" };

export function createAuth(cfg: AuthConfig): AuthService {
  const base = cfg.issuer.replace(/\/$/, "");
  const oidc = `${base}/protocol/openid-connect`;
  const host = cfg.hostedDomain?.replace(/\/$/, "");
  const navigate = cfg.navigate ?? ((u: string) => window.location.assign(u));
  const mgr = new Manager(
    {
      authority: base,
      client_id: cfg.clientId,
      redirect_uri: cfg.redirectUri,
      post_logout_redirect_uri: cfg.redirectUri,
      response_type: "code",
      scope: "openid email profile",
      // Static metadata: no discovery round trip. Keycloak path layout.
      metadata: host
        ? // Cognito: tokens are issued by `base` but served from the hosted-UI domain.
          {
            issuer: base,
            authorization_endpoint: `${host}/oauth2/authorize`,
            token_endpoint: `${host}/oauth2/token`,
            end_session_endpoint: `${host}/logout`,
            jwks_uri: `${base}/.well-known/jwks.json`,
          }
        : {
            issuer: base,
            authorization_endpoint: `${oidc}/auth`,
            token_endpoint: `${oidc}/token`,
            end_session_endpoint: `${oidc}/logout`,
            jwks_uri: `${oidc}/certs`,
          },
      userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
      stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
      automaticSilentRenew: true, // refresh-token renewal; no iframe
      loadUserInfo: false,
    },
    navigate,
  );

  let state: AuthState = { status: "loading" };
  let user: User | null = null;
  const subs = new Set<(s: AuthState) => void>();
  const set = (s: AuthState) => {
    state = s;
    subs.forEach((f) => f(s));
  };
  const expire = (notice: string) => {
    user = null;
    void mgr.removeUser();
    set({ status: "signed-out", notice });
  };
  const adopt = (u: User) => {
    user = u;
    set({ status: "signed-in", user: { accessToken: u.access_token, email: u.profile.email, name: u.profile.name } });
  };

  mgr.events.addUserLoaded((u) => {
    if (user) adopt(u);
  }); // silent renewal replaced the tokens
  mgr.events.addAccessTokenExpired(() => expire("Your session expired. Sign in again."));
  mgr.events.addSilentRenewError(() => expire("Your session expired. Sign in again."));

  const api = (path: string, token: string) =>
    fetch(`${cfg.apiBase ?? ""}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
    });

  return {
    providers: host ? ["google", "email"] : ["github", "google", "email"],
    async start() {
      const q = new URLSearchParams(window.location.search);
      if (!(q.has("code") || q.has("error")) || !q.has("state")) {
        set({ status: "signed-out" });
        return;
      }
      try {
        const u = await mgr.signinCallback(window.location.href);
        const returnTo = safeReturnTo((u?.state as { returnTo?: string } | undefined)?.returnTo);
        window.history.replaceState(null, "", returnTo); // drop code and state from the URL
        if (!u) {
          set({ status: "signed-out" });
          return;
        }
        user = u; // held in memory only; the UI stays signed out until the API accepts the sign-in
        // Records auth.sign_in and creates the user and personal org on first sign-in.
        const r = await api("/v1/auth/sign-in", u.access_token);
        if (!r.ok) {
          user = null;
          await mgr.removeUser();
          set({
            status: "signed-out",
            notice:
              r.status === 403 ? "Verify your email address, then sign in again." : "Sign-in was rejected. Try again.",
          });
          return;
        }
        adopt(u);
      } catch {
        user = null;
        window.history.replaceState(null, "", "/");
        set({ status: "signed-out", notice: "Sign-in failed. Try again." });
      }
    },
    async signIn(provider) {
      const hint = host ? COGNITO_IDPS[provider] : IDP_HINTS[provider];
      await mgr.redirectToSignin({
        state: { returnTo: safeReturnTo(window.location.pathname + window.location.search + window.location.hash) },
        extraQueryParams: hint ? { [host ? "identity_provider" : "kc_idp_hint"]: hint } : undefined,
      });
    },
    async signOut() {
      const u = user;
      user = null;
      set({ status: "signed-out" });
      if (!u) return;
      try {
        await api("/v1/auth/sign-out", u.access_token);
      } catch {
        /* the audit marker is best effort */
      }
      await mgr.removeUser();
      // Cognito's /logout wants client_id and logout_uri instead of the OIDC post_logout params.
      await mgr.redirectToSignout({
        id_token_hint: u.id_token,
        extraQueryParams: host ? { client_id: cfg.clientId, logout_uri: cfg.redirectUri } : undefined,
      });
    },
    token: () => (user && !user.expired ? user.access_token : undefined),
    getState: () => state,
    subscribe(fn) {
      subs.add(fn);
      return () => {
        subs.delete(fn);
      };
    },
  };
}
