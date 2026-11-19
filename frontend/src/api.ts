import { demoApi } from "./demo";
import type { AlertDetail, AlertFilters, AlertRow, AlertStatus, Overview, Page, Resolution, Rule } from "./types";

const BASE = import.meta.env.VITE_API_URL ?? "";

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* body was not JSON */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

const liveApi = {
  overview: () => http<Overview>("/api/stats/overview"),
  rules: () => http<Rule[]>("/api/rules"),
  mlHealth: () => http<{ status: string; modelLoaded: boolean; llmEnabled: boolean; llmModel: string | null }>("/api/ml/health"),

  alerts(f: AlertFilters, size = 25) {
    const p = new URLSearchParams();
    f.status.forEach((s) => p.append("status", s));
    f.severity.forEach((s) => p.append("severity", s));
    if (f.tactic) p.set("tactic", f.tactic);
    if (f.ruleId) p.set("ruleId", f.ruleId);
    if (f.q) p.set("q", f.q);
    p.set("sort", f.sort);
    p.set("dir", f.dir);
    p.set("page", String(f.page));
    p.set("size", String(size));
    return http<Page<AlertRow>>("/api/alerts?" + p.toString());
  },

  alert: (id: number) => http<AlertDetail>(`/api/alerts/${id}`),

  setStatus: (id: number, status: AlertStatus, actor: string, resolution?: Resolution, note?: string) =>
    http<AlertRow>(`/api/alerts/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status, resolution, note, actor }),
    }),

  bulkStatus: (ids: number[], status: AlertStatus, actor: string, resolution?: Resolution) =>
    http<{ updated: number }>("/api/alerts/bulk/status", {
      method: "POST",
      body: JSON.stringify({ ids, status, resolution, actor }),
    }),

  assign: (id: number, assignee: string, actor: string) =>
    http<AlertRow>(`/api/alerts/${id}/assignee`, { method: "PATCH", body: JSON.stringify({ assignee, actor }) }),

  note: (id: number, note: string, actor: string) =>
    http(`/api/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ note, actor }) }),

  summarize: (id: number) => http<{ summary: string; source: string }>(`/api/alerts/${id}/summary`, { method: "POST" }),

  runDetections: () => http<{ alertsCreated: number }>("/api/detections/run", { method: "POST" }),
};

/** On static hosting (Vercel) the dashboard runs against a bundled snapshot instead of the Java API. */
export const DEMO = import.meta.env.VITE_DEMO === "true";
export const api: typeof liveApi = DEMO ? demoApi : liveApi;
