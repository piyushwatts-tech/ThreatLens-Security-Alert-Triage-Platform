import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import { dateTime, label } from "../format";
import type { AlertDetail, Resolution } from "../types";
import { RESOLUTIONS } from "../types";
import { SeverityBadge, StatusBadge } from "./Badges";

interface Props {
  id: number;
  analyst: string;
  onClose: () => void;
  onChanged: () => void;
}

export function AlertDrawer({ id, analyst, onClose, onChanged }: Props) {
  const [d, setD] = useState<AlertDetail | null>(null);
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState<Resolution>("TRUE_POSITIVE");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.alert(id).then(setD).catch((e) => setErr(e.message));
  useEffect(() => { setD(null); load(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      await load();
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const a = d?.alert;
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" aria-label="Alert detail">
        <button className="close" onClick={onClose} aria-label="Close">×</button>
        {!a && !err && <div className="empty">Loading…</div>}
        {err && <div className="error">{err}</div>}
        {a && d && (
          <>
            <div className="drawer-head">
              <SeverityBadge severity={a.severity} score={a.riskScore} />
              <StatusBadge status={a.status} />
              {a.resolution && <span className="pill">{label(a.resolution)}</span>}
              <span className="mono muted">#{a.id} · {a.ruleId}</span>
            </div>
            <h2>{a.title}</h2>

            <div className="actions">
              {a.status === "NEW" && (
                <button className="primary" disabled={busy} onClick={() => act(() => api.setStatus(a.id, "INVESTIGATING", analyst))}>
                  Start investigating
                </button>
              )}
              {a.status !== "CLOSED" && (
                <span className="close-group">
                  <select value={resolution} onChange={(e) => setResolution(e.target.value as Resolution)} aria-label="Resolution">
                    {RESOLUTIONS.map((r) => <option key={r} value={r}>{label(r)}</option>)}
                  </select>
                  <button disabled={busy} onClick={() => act(() => api.setStatus(a.id, "CLOSED", analyst, resolution, note || undefined).then(() => setNote("")))}>
                    Close
                  </button>
                </span>
              )}
              {a.status === "CLOSED" && (
                <button disabled={busy} onClick={() => act(() => api.setStatus(a.id, "INVESTIGATING", analyst, undefined, "Reopened"))}>
                  Reopen
                </button>
              )}
              {a.assignee !== analyst && (
                <button className="link" disabled={busy} onClick={() => act(() => api.assign(a.id, analyst, analyst))}>
                  Assign to me
                </button>
              )}
            </div>

            <section>
              <div className="section-head">
                <h4>Triage summary</h4>
                <span className="muted small">{a.summarySource?.startsWith("llm") ? `AI · ${a.summarySource.slice(4)}` : "Template"}</span>
                <button className="link" disabled={busy} onClick={() => act(() => api.summarize(a.id))}>
                  {a.summarySource?.startsWith("llm") ? "Regenerate" : "Generate AI summary"}
                </button>
              </div>
              <pre className="summary">{a.summary}</pre>
            </section>

            <section className="grid2">
              <div>
                <h4>MITRE ATT&CK</h4>
                {a.mitreTechnique ? (
                  <a href={d.mitreUrl ?? "#"} target="_blank" rel="noreferrer" className="mitre">
                    <span className="mono">{a.mitreTechnique}</span> {a.mitreTechniqueName}
                    <span className="sub">{a.mitreTactic}</span>
                  </a>
                ) : <span className="muted">Unmapped</span>}
              </div>
              <div>
                <h4>Why this score</h4>
                <ul className="factors">
                  {Object.entries(a.scoreFactors).map(([k, v]) => (
                    <li key={k}><span>{k === "base" ? "Rule base" : k.replace(/([A-Z])/g, " $1").toLowerCase()}</span><b>{k === "base" ? v : `+${v}`}</b></li>
                  ))}
                  <li className="total"><span>Risk</span><b>{a.riskScore}/100</b></li>
                </ul>
              </div>
            </section>

            <section className="grid2">
              <div>
                <h4>Entities</h4>
                <dl className="kv">
                  {a.srcIp && (<><dt>Source IP</dt><dd className="mono">{a.srcIp}</dd></>)}
                  {a.dstIp && (<><dt>Destination</dt><dd className="mono">{a.dstIp}</dd></>)}
                  {a.host && (<><dt>Host</dt><dd className="mono">{a.host}</dd></>)}
                  {a.username && (<><dt>User</dt><dd className="mono">{a.username}</dd></>)}
                  <dt>First seen</dt><dd>{dateTime(a.firstSeen)}</dd>
                  <dt>Last seen</dt><dd>{dateTime(a.lastSeen)}</dd>
                  <dt>Events</dt><dd>{a.eventCount}</dd>
                  {a.anomalyScore != null && (<><dt>ML anomaly</dt><dd>{a.anomalyScore.toFixed(3)}</dd></>)}
                </dl>
              </div>
              <div>
                <h4>Playbook</h4>
                <ol className="playbook">{d.playbook.map((s) => <li key={s}>{s}</li>)}</ol>
              </div>
            </section>

            <section>
              <h4>Evidence</h4>
              <dl className="kv">
                {Object.entries(a.evidence).map(([k, v]) => (
                  <Fragment key={k}><dt>{k}</dt><dd className="mono wrap">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></Fragment>
                ))}
              </dl>
            </section>

            <section>
              <h4>Raw events ({d.events.length}{a.eventCount > d.events.length ? ` of ${a.eventCount}` : ""})</h4>
              <div className="table-wrap events">
                <table>
                  <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Target</th><th>User</th><th>Detail</th><th>Dataset label</th></tr></thead>
                  <tbody>
                    {d.events.map((e) => (
                      <tr key={e.id}>
                        <td className="small">{dateTime(e.time)}</td>
                        <td className="mono small">{e.type}</td>
                        <td className="mono small">{e.srcIp ?? ""}</td>
                        <td className="mono small">{e.dstIp ? `${e.dstIp}:${e.dstPort}` : e.host ?? ""}</td>
                        <td className="mono small">{e.username ?? ""}</td>
                        <td className="mono small wrap">{e.commandLine ?? (e.bytes != null ? `${e.packets} pkts / ${e.bytes} B` : "")}</td>
                        <td className="small">{e.datasetLabel ?? ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section>
              <h4>Activity</h4>
              <ul className="timeline">
                {d.activity.map((x) => (
                  <li key={x.id}>
                    <span className="small muted">{dateTime(x.createdAt)}</span>{" "}
                    <b>{x.actor}</b>{" "}
                    {x.action === "STATUS_CHANGE" ? <>moved {x.fromStatus} → {x.toStatus}</> : x.action.toLowerCase()}
                    {x.note && <div className="note">{x.note}</div>}
                  </li>
                ))}
              </ul>
              <div className="note-box">
                <textarea placeholder="Add an investigation note…" value={note} onChange={(e) => setNote(e.target.value)} />
                <button disabled={busy || !note.trim()} onClick={() => act(() => api.note(a.id, note, analyst).then(() => setNote("")))}>
                  Add note
                </button>
              </div>
            </section>
          </>
        )}
      </aside>
    </>
  );
}
