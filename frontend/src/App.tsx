import { useEffect, useState } from "react";
import { DEMO } from "./api";
import { AlertQueue } from "./components/AlertQueue";
import { Overview } from "./components/Overview";
import { Rules } from "./components/Rules";
import type { AlertFilters } from "./types";

type Tab = "overview" | "alerts" | "rules";

const DEFAULT_FILTERS: AlertFilters = {
  status: [], severity: [], tactic: "", ruleId: "", q: "", sort: "riskScore", dir: "desc", page: 0,
};

function readAnalyst(): string {
  try {
    return localStorage.getItem("threatlens.analyst") || "analyst";
  } catch {
    return "analyst";
  }
}

export default function App() {
  const [tab, setTab] = useState<Tab>(() => (location.hash.slice(1) as Tab) || "overview");
  const [filters, setFilters] = useState<AlertFilters>(DEFAULT_FILTERS);
  const [analyst, setAnalyst] = useState(readAnalyst);

  useEffect(() => { history.replaceState(null, "", "#" + tab); }, [tab]);
  useEffect(() => {
    try { localStorage.setItem("threatlens.analyst", analyst); } catch { /* storage unavailable */ }
  }, [analyst]);

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="22" height="22" aria-hidden>
            <circle cx="16" cy="16" r="12" fill="none" stroke="var(--series-1)" strokeWidth="4" />
            <circle cx="16" cy="16" r="4" fill="var(--sev-critical)" />
          </svg>
          ThreatLens
        </div>
        <nav>
          {(["overview", "alerts", "rules"] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
              {t === "overview" ? "Overview" : t === "alerts" ? "Alert queue" : "Detections"}
            </button>
          ))}
        </nav>
        <label className="analyst">
          Analyst
          <input value={analyst} onChange={(e) => setAnalyst(e.target.value.trim() || "analyst")} />
        </label>
      </header>
      {DEMO && (
        <div className="demo-banner">
          Live demo running on a snapshot of the seeded platform. Triage actions work but reset on reload.{" "}
          <a href="https://github.com/piyushwatts-tech/ThreatLens-Security-Alert-Triage-Platform" target="_blank" rel="noreferrer">
            Source and full stack setup
          </a>
        </div>
      )}
      <main>
        {tab === "overview" && (
          <Overview onDrill={(patch) => { setFilters({ ...DEFAULT_FILTERS, ...patch }); setTab("alerts"); }} />
        )}
        {tab === "alerts" && <AlertQueue filters={filters} setFilters={setFilters} analyst={analyst} />}
        {tab === "rules" && <Rules />}
      </main>
    </div>
  );
}
