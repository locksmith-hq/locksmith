import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import type { StatusView } from "@locksmith/api-types";
import * as api from "./api";
import { Icon, Logo, Wordmark, type IconName } from "./brand";
import { Audit, Keys, Overview, Relays, Sessions, Tokens, clock, errCode, msg, plural, type ScreenProps } from "./screens";

const TABS = { Overview, Sessions, Keys, Tokens, Relays, Audit } as const;
export type Tab = keyof typeof TABS;
const TAB_ICON: Record<Tab, IconName> = { Overview: "grid", Sessions: "sessions", Keys: "key", Tokens: "token", Relays: "relay", Audit: "doc" };
const POLL_MS = 5000;

type Appearance = "system" | "light" | "dark";
const APPEARANCE: { v: Appearance; label: string; icon: IconName }[] = [
  { v: "system", label: "System", icon: "monitor" }, { v: "light", label: "Light", icon: "sun" }, { v: "dark", label: "Dark", icon: "moon" },
];
const PREF = "locksmith.appearance";
const readPref = (): Appearance => {
  try { const v = localStorage.getItem(PREF); return v === "light" || v === "dark" ? v : "system"; } catch { return "system"; }
};

/** Sets `data-theme` on <html> from the stored choice, following the system while it is "system". */
function useAppearance() {
  const [pref, setPref] = useState<Appearance>(readPref);
  useLayoutEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const apply = () => { document.documentElement.dataset.theme = pref === "system" ? (mq?.matches ? "dark" : "light") : pref; };
    apply();
    mq?.addEventListener?.("change", apply);
    try { if (pref === "system") localStorage.removeItem(PREF); else localStorage.setItem(PREF, pref); } catch { /* storage blocked: keep the choice for this window only */ }
    return () => mq?.removeEventListener?.("change", apply);
  }, [pref]);
  return [pref, setPref] as const;
}

/** `since`: when the vault last changed to its current state, from the ledger's UNLOCK/LOCK events. */
interface Counts { tokens?: number; relays?: number; since?: Partial<Record<"UNLOCK" | "LOCK", number>> }

export function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const [st, setSt] = useState<StatusView | null>(null);
  const [down, setDown] = useState<string | null>(null);
  const [counts, setCounts] = useState<Counts>({});
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [appearance, setAppearance] = useAppearance();

  const refresh = useCallback(async () => {
    try {
      setSt(await api.status());
      setDown(null);
    } catch (e) {
      // A poll never hides an action error; only "daemon gone" replaces the screen.
      if (errCode(e) === "Unavailable") { setDown(msg(e)); setSt(null); }
      return;
    }
    // Sidebar counts are best effort: a failure leaves the count off, never an error.
    const [t, r, a] = await Promise.allSettled([api.tokenList(), api.relayInfo(), api.auditList(200)]);
    const since: Counts["since"] = {};
    if (a.status === "fulfilled") for (const e of a.value ?? []) if (e.action === "UNLOCK" || e.action === "LOCK") since[e.action] = e.ts;
    setCounts({
      since,
      tokens: t.status === "fulfilled" ? t.value?.length : undefined,
      relays: r.status === "fulfilled" && r.value ? [r.value.git_port, r.value.http_port, r.value.aws_port].filter((p) => p != null).length : undefined,
    });
  }, []);
  useEffect(() => {
    void refresh();
    const t = setInterval(() => { if (document.visibilityState !== "hidden") void refresh(); }, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const act: ScreenProps["act"] = useCallback(async (fn, label) => {
    setErr("");
    setNote("");
    try {
      const r = await fn();
      const l = label?.(r);
      if (l) setNote(l);
    } catch (e) {
      setErr(msg(e));
    }
    await refresh();
  }, [refresh]);

  const live = st ? st.leases.filter((l) => l.state === "active") : [];
  const Screen = TABS[tab];
  const open = st ? !st.locked : false;
  const count: Partial<Record<Tab, number>> = { Overview: st ? live.length : undefined, Sessions: st ? live.length : undefined, Tokens: counts.tokens, Relays: counts.relays };
  const lock = () => act(api.lock, () => "Vault locked");
  const unlock = () => act(api.unlockSecure, (r) => (r === "cancelled" ? "Unlock cancelled, the vault stays locked" : ""));
  const revokeAll = () => act(() => api.revoke(null), (n) => `Revoked ${plural(n, "session")}`);
  const since = counts.since?.[open ? "UNLOCK" : "LOCK"];

  return (
    <div className="app">
      <aside className="side">
        <div className="brand"><Logo open={open} /><Wordmark /></div>
        <nav className="nav" aria-label="Main">
          {(Object.keys(TABS) as Tab[]).map((t) => (
            <button key={t} type="button" aria-current={t === tab ? "page" : undefined} onClick={() => setTab(t)}>
              <Icon name={TAB_ICON[t]} />{t}
              {count[t] !== undefined && <span className="count">{count[t]}</span>}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <fieldset className="seg">
            <legend className="sr-only">Appearance</legend>
            {APPEARANCE.map((a) => (
              <label key={a.v} title={`Appearance: ${a.label}`}>
                <input type="radio" name="appearance" value={a.v} checked={appearance === a.v} onChange={() => setAppearance(a.v)} />
                <Icon name={a.icon} />{a.label}
              </label>
            ))}
          </fieldset>
          <p className="daemon" data-up={!down && !!st}>
            <span className="dot" aria-hidden="true" />
            <span><b>locksmithd</b> · {down ? "not running" : st ? "running" : "connecting"}</span>
          </p>
        </div>
      </aside>

      <div className="work">
        {down ? (
          <main className="down" aria-labelledby="h-down">
            <span className="down-ic"><Icon name="power" /></span>
            <h1 id="h-down">The Locksmith daemon is not running</h1>
            <p>This window reads everything from <code>locksmithd</code>. Start it in a terminal; this window reconnects on its own within a few seconds.</p>
            <pre><code>locksmithd</code></pre>
            <p className="muted small">Detail: {down}</p>
          </main>
        ) : (
          <>
            <header className="vault" aria-label="Vault" data-open={open}>
              <div className="vault-line" aria-live="polite" aria-atomic="true">
                <span className="vault-k">Vault</span>
                {st ? (
                  <>
                    <b className="vault-state"><span className="dot" aria-hidden="true" />{open ? "Unlocked" : "Locked"}</b>
                    <span className="vault-meta">
                      {open ? <span>{plural(live.length, "session")}</span> : <span>Agents cannot start sessions or use keys</span>}
                      {since !== undefined && <span>since <time className="mono" dateTime={new Date(since * 1000).toISOString()}>{clock(since)}</time></span>}
                    </span>
                  </>
                ) : <span className="vault-meta">Reading the vault…</span>}
                {note && <span className="vault-note">{note}</span>}
              </div>
              {st && (
                <div className="acts">
                  <button type="button" className="btn quiet danger-text" aria-label="Revoke all sessions" disabled={!live.length} onClick={revokeAll}>Revoke all</button>
                  {open
                    ? <button type="button" className="btn primary" onClick={lock}><Icon name="lock" />Lock vault</button>
                    : <button type="button" className="btn primary" title="Opens a native Locksmith prompt; the passphrase never enters this window" onClick={unlock}><Icon name="unlock" />Unlock vault</button>}
                </div>
              )}
            </header>
            <main>
              {err && <p role="alert" className="alert"><Icon name="alert" />{err}</p>}
              <Screen st={st} act={act} go={setTab} />
            </main>
          </>
        )}
      </div>
    </div>
  );
}
