export function timeAgo(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function dateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function hour(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export const label = (s: string) => s.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());

export function entity(a: { srcIp: string | null; dstIp: string | null; host: string | null; username: string | null }) {
  const parts: string[] = [];
  if (a.srcIp) parts.push(a.srcIp);
  if (a.dstIp) parts.push("→ " + a.dstIp);
  if (a.host && !a.dstIp) parts.push((a.srcIp ? "→ " : "") + a.host);
  if (a.username) parts.push("· " + a.username);
  return parts.join(" ");
}
