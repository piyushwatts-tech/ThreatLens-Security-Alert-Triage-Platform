import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { entity, timeAgo } from "../format";
import type { AlertFilters, AlertRow, Page, Rule } from "../types";
import { SEVERITIES, STATUSES } from "../types";
import { SeverityBadge, StatusBadge } from "./Badges";
import { AlertDrawer } from "./AlertDrawer";

interface Props {
  filters: AlertFilters;
  setFilters: (f: AlertFilters) => void;
  analyst: string;
}

const TACTICS = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access",
  "Discovery", "Command and Control", "Exfiltration", "Impact"];

export function AlertQueue({ filters, setFilters, analyst }: Props) {
  const [page, setPage] = useState<Page<AlertRow> | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const [q, setQ] = useState(filters.q);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.alerts(filters).then((p) => { setPage(p); setErr(null); }).catch((e) => setErr(e.message));
  }, [filters]);

  useEffect(load, [load]);
  useEffect(() => { api.rules().then(setRules).catch(() => {}); }, []);
  useEffect(() => {
    const t = setTimeout(() => q !== filters.q && setFilters({ ...filters, q, page: 0 }), 300);
    return () => clearTimeout(t);
  }, [q]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggle = <T,>(list: T[], v: T) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const sortBy = (col: string) =>
    setFilters({ ...filters, sort: col, dir: filters.sort === col && filters.dir === "desc" ? "asc" : "desc", page: 0 });
  const arrow = (col: string) => (filters.sort === col ? (filters.dir === "desc" ? " ↓" : " ↑") : "");

  async function bulk(status: "INVESTIGATING" | "CLOSED") {
    const ids = [...checked];
    if (!ids.length) return;
    await api.bulkStatus(ids, status, analyst, status === "CLOSED" ? "FALSE_POSITIVE" : undefined);
    setChecked(new Set());
    load();
  }

  const pages = page ? Math.max(1, Math.ceil(page.total / page.size)) : 1;

  return (
    <div className="queue">
      <div className="filters">
        <input className="search" placeholder="Search IP, host, user, technique…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="chips" aria-label="Severity filter">
          {SEVERITIES.map((s) => (
            <button key={s} className={`chip ${filters.severity.includes(s) ? "on" : ""}`}
                    onClick={() => setFilters({ ...filters, severity: toggle(filters.severity, s), page: 0 })}>
              <span className={`dot dot-${s.toLowerCase()}`} /> {s}
            </button>
          ))}
        </div>
        <div className="chips" aria-label="Status filter">
          {STATUSES.map((s) => (
            <button key={s} className={`chip ${filters.status.includes(s) ? "on" : ""}`}
                    onClick={() => setFilters({ ...filters, status: toggle(filters.status, s), page: 0 })}>
              {s === "INVESTIGATING" ? "Investigating" : s === "NEW" ? "New" : "Closed"}
            </button>
          ))}
        </div>
        <select value={filters.tactic} onChange={(e) => setFilters({ ...filters, tactic: e.target.value, page: 0 })}>
          <option value="">All tactics</option>
          {TACTICS.map((t) => <option key={t}>{t}</option>)}
        </select>
        <select value={filters.ruleId} onChange={(e) => setFilters({ ...filters, ruleId: e.target.value, page: 0 })}>
          <option value="">All rules</option>
          {rules.map((r) => <option key={r.id} value={r.id}>{r.id} {r.name}</option>)}
        </select>
        {(filters.severity.length || filters.status.length || filters.tactic || filters.ruleId || filters.q) ? (
          <button className="link" onClick={() => { setQ(""); setFilters({ ...filters, severity: [], status: [], tactic: "", ruleId: "", q: "", page: 0 }); }}>
            Clear filters
          </button>
        ) : null}
      </div>

      {checked.size > 0 && (
        <div className="bulkbar">
          {checked.size} selected
          <button onClick={() => bulk("INVESTIGATING")}>Start investigating</button>
          <button onClick={() => bulk("CLOSED")}>Close as false positive</button>
          <button className="link" onClick={() => setChecked(new Set())}>Clear</button>
        </div>
      )}

      {err && <div className="error">{err}</div>}

      <div className="table-wrap">
        <table className="alerts">
          <thead>
            <tr>
              <th className="cb">
                <input type="checkbox" aria-label="Select all"
                       checked={!!page?.items.length && page.items.every((a) => checked.has(a.id))}
                       onChange={(e) => setChecked(e.target.checked ? new Set(page?.items.map((a) => a.id)) : new Set())} />
              </th>
              <th className="sortable" onClick={() => sortBy("riskScore")}>Severity{arrow("riskScore")}</th>
              <th>Alert</th>
              <th>ATT&CK</th>
              <th>Entities</th>
              <th className="sortable" onClick={() => sortBy("status")}>Status{arrow("status")}</th>
              <th className="sortable" onClick={() => sortBy("firstSeen")}>First seen{arrow("firstSeen")}</th>
            </tr>
          </thead>
          <tbody>
            {page?.items.map((a) => (
              <tr key={a.id} className={selected === a.id ? "sel" : ""} onClick={() => setSelected(a.id)}>
                <td className="cb" onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" aria-label={`Select alert ${a.id}`} checked={checked.has(a.id)}
                         onChange={() => setChecked((c) => { const n = new Set(c); n.has(a.id) ? n.delete(a.id) : n.add(a.id); return n; })} />
                </td>
                <td><SeverityBadge severity={a.severity} score={a.riskScore} /></td>
                <td>
                  <div className="title">{a.title}</div>
                  <div className="sub mono">{a.ruleId} · {a.eventCount} events{a.anomalyScore != null ? ` · ML ${a.anomalyScore.toFixed(2)}` : ""}</div>
                </td>
                <td>
                  <div className="mono">{a.mitreTechnique ?? "n/a"}</div>
                  <div className="sub">{a.mitreTactic}</div>
                </td>
                <td className="mono small">{entity(a)}</td>
                <td>
                  <StatusBadge status={a.status} />
                  {a.assignee && <div className="sub">@{a.assignee}</div>}
                </td>
                <td className="small" title={a.firstSeen}>{timeAgo(a.firstSeen)}</td>
              </tr>
            ))}
            {page && page.items.length === 0 && (
              <tr><td colSpan={7} className="empty">No alerts match these filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {page && (
        <div className="pager">
          <span>{page.total} alerts</span>
          <button disabled={filters.page === 0} onClick={() => setFilters({ ...filters, page: filters.page - 1 })}>Prev</button>
          <span>Page {filters.page + 1} / {pages}</span>
          <button disabled={filters.page + 1 >= pages} onClick={() => setFilters({ ...filters, page: filters.page + 1 })}>Next</button>
        </div>
      )}

      {selected != null && (
        <AlertDrawer id={selected} analyst={analyst} onClose={() => setSelected(null)} onChanged={load} />
      )}
    </div>
  );
}
