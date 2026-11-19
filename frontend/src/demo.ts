/**
 * Demo mode: serves the dashboard from a snapshot of real API responses
 * (public/demo-data.json, captured from the seeded stack) so it can run on
 * static hosting with no backend. Triage actions work in memory and reset on reload.
 * Timestamps are shifted so the snapshot always looks recent.
 */
import type {
  Activity, AlertDetail, AlertFilters, AlertRow, AlertStatus, Overview, Page, Resolution, Rule, Severity,
} from "./types";

interface Snapshot {
  generatedAt: string;
  overview: Overview;
  rules: Rule[];
  mlHealth: { status: string; modelLoaded: boolean; llmEnabled: boolean; llmModel: string | null };
  details: Record<string, AlertDetail>;
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const SEV_RANK: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const TRANSITIONS: Record<AlertStatus, AlertStatus[]> = {
  NEW: ["INVESTIGATING", "CLOSED"], INVESTIGATING: ["CLOSED", "NEW"], CLOSED: ["INVESTIGATING"],
};

let snapshot: Promise<Snapshot> | null = null;
let nextActivityId = 1_000_000;

function shiftTimes<T>(value: T, deltaMs: number): T {
  if (typeof value === "string" && ISO.test(value)) {
    return new Date(new Date(value).getTime() + deltaMs).toISOString() as T;
  }
  if (Array.isArray(value)) return value.map((v) => shiftTimes(v, deltaMs)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = shiftTimes(v, deltaMs);
    return out as T;
  }
  return value;
}

function load(): Promise<Snapshot> {
  if (!snapshot) {
    snapshot = fetch("/demo-data.json")
      .then((r) => r.json() as Promise<Snapshot>)
      .then((s) => shiftTimes(s, Date.now() - new Date(s.generatedAt).getTime()));
  }
  return snapshot;
}

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v));

function row(d: AlertDetail): AlertRow {
  const a = d.alert;
  return {
    id: a.id, ruleId: a.ruleId, title: a.title, severity: a.severity, riskScore: a.riskScore, status: a.status,
    resolution: a.resolution, assignee: a.assignee, mitreTactic: a.mitreTactic, mitreTechnique: a.mitreTechnique,
    mitreTechniqueName: a.mitreTechniqueName, srcIp: a.srcIp, dstIp: a.dstIp, host: a.host, username: a.username,
    firstSeen: a.firstSeen, lastSeen: a.lastSeen, eventCount: a.eventCount, anomalyScore: a.anomalyScore,
  };
}

async function detail(id: number): Promise<AlertDetail> {
  const d = (await load()).details[String(id)];
  if (!d) throw new Error(`Alert ${id} not found`);
  return d;
}

function log(d: AlertDetail, actor: string, action: string, from: AlertStatus | null, to: AlertStatus | null, note?: string) {
  const entry: Activity = {
    id: nextActivityId++, actor, action, fromStatus: from, toStatus: to, note: note ?? null,
    createdAt: new Date().toISOString(),
  };
  d.activity.push(entry);
}

function changeStatus(d: AlertDetail, next: AlertStatus, actor: string, resolution?: Resolution, note?: string) {
  const a = d.alert;
  if (a.status === next) return;
  if (!TRANSITIONS[a.status].includes(next)) throw new Error(`Cannot move alert from ${a.status} to ${next}`);
  if (next === "CLOSED" && !resolution) throw new Error("Closing an alert requires a resolution");
  const prev = a.status;
  a.status = next;
  a.resolution = next === "CLOSED" ? resolution! : null;
  if (next === "INVESTIGATING" && !a.assignee) a.assignee = actor;
  const text = next === "CLOSED" ? `Resolution: ${resolution}${note ? `. ${note}` : ""}` : note;
  log(d, actor, "STATUS_CHANGE", prev, next, text);
}

export const demoApi = {
  async overview(): Promise<Overview> {
    const s = await load();
    const all = Object.values(s.details).map((d) => d.alert);
    const bySeverity = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 } as Record<Severity, number>;
    const byStatus = { NEW: 0, INVESTIGATING: 0, CLOSED: 0 } as Record<AlertStatus, number>;
    all.forEach((a) => { bySeverity[a.severity]++; byStatus[a.status]++; });
    return {
      ...clone(s.overview),
      totalAlerts: all.length,
      openAlerts: all.length - byStatus.CLOSED,
      openCritical: all.filter((a) => a.severity === "CRITICAL" && a.status !== "CLOSED").length,
      bySeverity,
      byStatus,
    };
  },

  rules: async () => clone((await load()).rules),
  mlHealth: async () => clone((await load()).mlHealth),

  async alerts(f: AlertFilters, size = 25): Promise<Page<AlertRow>> {
    const q = f.q.trim().toLowerCase();
    let rows = Object.values((await load()).details).map(row).filter((a) =>
      (!f.status.length || f.status.includes(a.status)) &&
      (!f.severity.length || f.severity.includes(a.severity)) &&
      (!f.tactic || a.mitreTactic === f.tactic) &&
      (!f.ruleId || a.ruleId === f.ruleId) &&
      (!q || [a.title, a.srcIp, a.dstIp, a.host, a.username, a.mitreTechnique]
        .some((v) => v?.toLowerCase().includes(q))));
    const dir = f.dir === "asc" ? 1 : -1;
    const key = (a: AlertRow): number | string =>
      f.sort === "severity" ? SEV_RANK[a.severity] : f.sort === "firstSeen" ? a.firstSeen
        : f.sort === "status" ? a.status : f.sort === "eventCount" ? a.eventCount : a.riskScore;
    rows = rows.sort((x, y) => (key(x) < key(y) ? -dir : key(x) > key(y) ? dir : y.firstSeen.localeCompare(x.firstSeen)));
    return { items: rows.slice(f.page * size, (f.page + 1) * size), total: rows.length, page: f.page, size };
  },

  alert: async (id: number) => clone(await detail(id)),

  async setStatus(id: number, status: AlertStatus, actor: string, resolution?: Resolution, note?: string) {
    const d = await detail(id);
    changeStatus(d, status, actor, resolution, note);
    return row(d);
  },

  async bulkStatus(ids: number[], status: AlertStatus, actor: string, resolution?: Resolution) {
    let updated = 0;
    for (const id of ids) {
      const d = await detail(id);
      if (d.alert.status !== status && TRANSITIONS[d.alert.status].includes(status)) {
        changeStatus(d, status, actor, resolution);
        updated++;
      }
    }
    return { updated };
  },

  async assign(id: number, assignee: string, actor: string) {
    const d = await detail(id);
    d.alert.assignee = assignee || null;
    log(d, actor, "ASSIGNED", d.alert.status, d.alert.status, assignee ? `Assigned to ${assignee}` : "Unassigned");
    return row(d);
  },

  async note(id: number, note: string, actor: string) {
    const d = await detail(id);
    log(d, actor, "NOTE", d.alert.status, d.alert.status, note);
    return d.activity[d.activity.length - 1];
  },

  async summarize(id: number) {
    const a = (await detail(id)).alert;
    return { summary: a.summary ?? "", source: a.summarySource ?? "template" };
  },

  runDetections: async () => ({ alertsCreated: 0 }),
};
