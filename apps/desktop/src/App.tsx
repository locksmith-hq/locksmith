import { useCallback, useEffect, useState } from "react";
import type { StatusView } from "@locksmith/api-types";
import * as api from "./api";
import { Mark, Plug } from "./brand";
import { Audit, Keys, Overview, Relays, Tokens, errCode, msg, type ScreenProps } from "./screens";

const TABS = { Overview, Keys, Tokens, Relays, Audit } as const;
type Tab = keyof typeof TABS;
const POLL_MS = 5000;

export function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const [st, setSt] = useState<StatusView | null>(null);
  const [down, setDown] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const refresh = useCallback(async () => {
    try {
      setSt(await api.status());
      setDown(null);
    } catch (e) {
      // A poll never hides an action error; only "daemon gone" replaces the screen.
      if (errCode(e) === "Unavailable") { setDown(msg(e)); setSt(null); }
    }
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
  const struck = st ? st.leases.length - live.length : 0;
  const Screen = TABS[tab];
  const open = st ? !st.locked : false;

  return (
    <div className="app">
      <aside className="rail">
        <div className="brand"><Mark size={22} />Locksmith</div>
        <nav aria-label="Main">
          {(Object.keys(TABS) as Tab[]).map((t) => (
            <button key={t} type="button" aria-current={t === tab ? "page" : undefined} onClick={() => setTab(t)}>
              <i aria-hidden="true" />{t}
            </button>
          ))}
        </nav>
        {st && (
          <p className="rail-foot">
            {live.length} {live.length === 1 ? "active session" : "active sessions"}
            {struck > 0 && <><br />{struck} struck</>}
          </p>
        )}
      </aside>

      <div className="work">
        <header className="band">
          <div className="vault" aria-live="polite" aria-atomic="true">
            <span className="vault-name">Vault</span>
            <strong className="vault-state" data-open={open}>
              {st ? (st.locked ? "Locked" : "Unlocked") : down ? "Not connected" : "Reading…"}
            </strong>
            {note && <span className="vault-note">{note}</span>}
          </div>
          <div className="band-actions">
            {st && (st.locked
              ? <button type="button" className="btn primary" onClick={() => act(api.unlockSecure, (r) => (r === "cancelled" ? "Unlock cancelled" : ""))}>Unlock</button>
              : <button type="button" className="btn" onClick={() => act(api.lock)}>Lock now</button>)}
            {st && (
              <button
                type="button" className="btn danger" disabled={!live.length}
                onClick={() => act(() => api.revoke(null), (n) => `Revoked ${n} ${n === 1 ? "session" : "sessions"}`)}
              >Revoke all sessions</button>
            )}
          </div>
          <Plug open={open} />
        </header>
        {err && <p role="alert" className="alert">{err}</p>}

        {down ? (
          <main className="down" aria-labelledby="h-down">
            <Mark locked size={40} />
            <h1 id="h-down">The Locksmith daemon is not running</h1>
            <p>This window reads everything from <code>locksmithd</code>. Start it in a terminal and the schedule comes back on its own within a few seconds.</p>
            <pre><code>locksmithd</code></pre>
            <p className="quiet">Detail: {down}</p>
          </main>
        ) : (
          <main><Screen st={st} act={act} /></main>
        )}
      </div>
    </div>
  );
}
