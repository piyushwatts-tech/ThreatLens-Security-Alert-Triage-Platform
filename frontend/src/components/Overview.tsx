import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { hour } from "../format";
import type { Overview as OverviewData, Severity } from "../types";
import { SEVERITIES } from "../types";

export const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

interface Props {
  onDrill: (patch: { severity?: Severity[]; status?: ("NEW" | "INVESTIGATING")[]; tactic?: string }) => void;
}

function Tip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + p.value, 0);
  return (
    <div className="tip">
      <div className="tip-title">{label}</div>
      {payload.filter((p) => p.value > 0).map((p) => (
        <div key={p.name} className="tip-row">
          <span className="swatch" style={{ background: p.color }} /> {p.name} <b>{p.value}</b>
        </div>
      ))}
      <div className="tip-row muted">Total <b>{total}</b></div>
    </div>
  );
}

export function Overview({ onDrill }: Props) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const load = () => api.overview().then((d) => { setData(d); setErr(null); }).catch((e) => setErr(String(e.message ?? e)));
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  if (err) return <div className="empty">Could not reach the API: {err}</div>;
  if (!data)
    return (
      <div className="empty">
        Loading…{import.meta.env.VITE_API_URL && " The hosted API sleeps when idle, so the first load can take up to a minute."}
      </div>
    );
  if (data.totalAlerts === 0)
    return (
      <div className="empty">
        No alerts yet. Load the sample data with <code>./scripts/seed.sh</code> or upload a dataset to <code>/api/ingest</code>.
      </div>
    );

  const timeline = data.timeline.map((t) => ({
    t: hour(t.bucket), CRITICAL: t.critical, HIGH: t.high, MEDIUM: t.medium, LOW: t.low,
  }));
  const tactics = data.byTactic.map((c) => ({ tactic: c.key, alerts: c.count }));
  const events = data.eventsBySource.reduce((s, c) => s + c.count, 0);

  return (
    <div className="overview">
      <div className="kpis">
        <button className="kpi kpi-critical" onClick={() => onDrill({ severity: ["CRITICAL"], status: ["NEW", "INVESTIGATING"] })}>
          <span className="kpi-label">▲ Open critical</span>
          <span className="kpi-value">{data.openCritical}</span>
          <span className="kpi-sub">needs eyes now</span>
        </button>
        <button className="kpi" onClick={() => onDrill({ status: ["NEW", "INVESTIGATING"] })}>
          <span className="kpi-label">Open alerts</span>
          <span className="kpi-value">{data.openAlerts}</span>
          <span className="kpi-sub">{data.byStatus.NEW} new · {data.byStatus.INVESTIGATING} investigating</span>
        </button>
        <div className="kpi">
          <span className="kpi-label">Closed</span>
          <span className="kpi-value">{data.byStatus.CLOSED}</span>
          <span className="kpi-sub">
            {data.meanMinutesToClose != null ? `mean time to close ${formatMinutes(data.meanMinutesToClose)}` : "none closed yet"}
          </span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Events analysed</span>
          <span className="kpi-value">{events.toLocaleString()}</span>
          <span className="kpi-sub">{data.eventsBySource.map((c) => `${c.key} ${c.count.toLocaleString()}`).join(" · ")}</span>
        </div>
      </div>

      <div className="sev-strip" role="list" aria-label="Alerts by severity">
        {SEVERITIES.map((s) => (
          <button key={s} role="listitem" className="sev-cell" onClick={() => onDrill({ severity: [s] })}>
            <span className={`sev sev-${s.toLowerCase()}`}>{s}</span>
            <span className="sev-count">{data.bySeverity[s]}</span>
            <span className="sev-bar">
              <span style={{ width: `${(data.bySeverity[s] / Math.max(1, data.totalAlerts)) * 100}%`, background: SEV_COLOR[s] }} />
            </span>
          </button>
        ))}
      </div>

      <div className="charts">
        <section className="card">
          <h3>Alerts over time, by severity</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={timeline} barCategoryGap="20%">
              <CartesianGrid vertical={false} stroke="var(--grid)" />
              <XAxis dataKey="t" tick={{ fill: "var(--text-2)", fontSize: 12 }} axisLine={{ stroke: "var(--grid)" }} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "var(--text-2)", fontSize: 12 }} axisLine={false} tickLine={false} width={28} />
              <Tooltip content={<Tip />} cursor={{ fill: "var(--hover)" }} />
              <Legend iconType="square" wrapperStyle={{ fontSize: 12 }} formatter={(v: string) => <span style={{ color: "var(--text-2)" }}>{v}</span>} />
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s, i, arr) => (
                <Bar key={s} dataKey={s} stackId="sev" fill={SEV_COLOR[s as Severity]} stroke="var(--surface)" strokeWidth={2}
                     radius={i === arr.length - 1 ? [4, 4, 0, 0] : 0} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="card">
          <h3>MITRE ATT&CK tactics</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={tactics} layout="vertical" margin={{ left: 8, right: 24 }}>
              <CartesianGrid horizontal={false} stroke="var(--grid)" />
              <XAxis type="number" allowDecimals={false} tick={{ fill: "var(--text-2)", fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="tactic" width={120} tick={{ fill: "var(--text-1)", fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip content={<Tip />} cursor={{ fill: "var(--hover)" }} />
              <Bar dataKey="alerts" name="Alerts" fill="var(--series-1)" radius={[0, 4, 4, 0]} barSize={14}
                   onClick={(d: { tactic?: string }) => d.tactic && onDrill({ tactic: d.tactic })} style={{ cursor: "pointer" }} />
            </BarChart>
          </ResponsiveContainer>
          <p className="hint">Click a bar to filter the queue.</p>
        </section>
      </div>

      <section className="card">
        <h3>Top detections</h3>
        <table className="mini">
          <tbody>
            {data.byRule.slice(0, 8).map((r) => (
              <tr key={r.key}>
                <td className="mono">{r.key.split(" ")[0]}</td>
                <td>{r.key.split(" ").slice(1).join(" ")}</td>
                <td className="num">{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function formatMinutes(m: number) {
  if (m < 1) return `${Math.round(m * 60)}s`;
  if (m < 120) return `${Math.round(m)} min`;
  return `${(m / 60).toFixed(1)} h`;
}
