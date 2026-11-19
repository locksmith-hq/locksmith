// Security product: the detail view for one finding.
import { useState } from "react";
import { Crumbs, Empty, Head, Icon, ago } from "../kit";
import { dismiss, href, mask, reopen, resolve, sevLabel, useWorld } from "./securityStore";

export function FindingView({ id, say }: { id: string; say: (note: string) => void }) {
  const [w, setW] = useWorld();
  const [asking, setAsking] = useState(false);
  const f = w.findings.find((x) => x.id === id);
  if (!f) {
    return (
      <section>
        <Crumbs trail={[["Findings", href("findings")], ["Not found"]]} />
        <Empty icon="search"><b>No such finding.</b> It may have been removed. <a className="link" href={href("findings")}>Back to findings</a></Empty>
      </section>
    );
  }
  const [project] = f.secret?.split("/") ?? [];
  const open = f.status === "Open";
  return (
    <section>
      <Crumbs trail={[["Findings", href("findings")], [f.kind]]} />
      <Head title={f.kind} sub={`Found in ${f.srcName}, first seen ${ago(f.first)}. The value is always hidden here.`}>
        {open
          ? <button type="button" className="btn primary" onClick={() => { setW(resolve(w, f.id)); say("Marked resolved"); }}>Mark resolved</button>
          : <button type="button" className="btn primary" onClick={() => { setW(reopen(w, f.id)); say("Finding reopened"); }}>Reopen finding</button>}
      </Head>
      <div className="detail-cols sc-cols">
        <div className="sc-stack"><section className="panel" aria-labelledby="fd-what">
          <h2 id="fd-what">What and where</h2>
          <dl className="sc-facts">
            {([
              ["Where", <>{f.srcName}<div className="mono muted">{f.spot}</div></>],
              ["Added by", f.who],
              ["Severity", <span key="s" className="sev" data-sev={f.sev.toLowerCase()}>{sevLabel(f)}</span>],
              ["Status", <span key="t">{f.status}{f.rotationOpened && open && <span className="badge">Rotation opened</span>}{f.reason && <span className="muted"> ({f.reason})</span>}</span>],
            ] as [string, React.ReactNode][]).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}
          </dl>
          <h3>Around the line, value hidden</h3>
          <pre className="excerpt mono" aria-label="Code around the finding, with the value hidden">{f.lines.map(([n, t, hit]) => <div key={n} data-hit={hit}><span>{n}</span><span>{mask(t)}</span></div>)}</pre>
        </section></div>
        <div className="sc-stack">
          <section className="panel" aria-labelledby="fd-secret">
            <h2 id="fd-secret">Matching Locksmith secret</h2>
            {f.secret && project ? (
              <>
                <p className="small"><span className="mono strong">{f.secret}</span> is stored in Locksmith. {f.rotated ? "It has been rotated, so the exposed value no longer works." : "Rotate it so the exposed value stops working."}</p>
                {f.rotationOpened && !f.rotated && <p className="small">A rotation was opened automatically. You still approve the new value.</p>}
                <p style={{ margin: "10px 0 0" }}><a className="btn sm" href={`#/secrets/${project}/rotation`}><Icon name="rotate" />Open rotation for {project}</a></p>
              </>
            ) : <p className="small muted">No Locksmith secret matches this value. Revoke it where it was issued and create a new one.</p>}
          </section>
          <section className="panel" aria-labelledby="fd-act">
            <h2 id="fd-act">Not a real secret?</h2>
            {asking ? (
              <form className="inline-form" onSubmit={(e) => { e.preventDefault(); setW(dismiss(w, f.id, String(new FormData(e.currentTarget).get("reason")))); setAsking(false); say("Marked as not a secret"); }}>
                <input name="reason" aria-label="Why is this not a secret?" placeholder="Why is this not a secret?" required autoFocus autoComplete="off" />
                <button type="submit" className="btn sm">Save reason</button>
                <button type="button" className="btn sm quiet" onClick={() => setAsking(false)}>Cancel</button>
              </form>
            ) : open ? (
              <button type="button" className="btn sm quiet" onClick={() => setAsking(true)}>Not a secret</button>
            ) : <p className="small muted">{f.status === "Resolved" ? "This finding is resolved." : "This finding was dismissed."} Reopen it if that was a mistake.</p>}
          </section>
        </div>
      </div>
    </section>
  );
}
