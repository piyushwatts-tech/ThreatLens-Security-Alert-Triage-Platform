import type { AlertStatus, Severity } from "../types";

const SEV_ICON: Record<Severity, string> = { CRITICAL: "▲", HIGH: "◆", MEDIUM: "●", LOW: "○" };

/** Severity always ships with an icon + text label: never color alone. */
export function SeverityBadge({ severity, score }: { severity: Severity; score?: number }) {
  return (
    <span className={`sev sev-${severity.toLowerCase()}`} title={score != null ? `Risk ${score}/100` : undefined}>
      <span aria-hidden>{SEV_ICON[severity]}</span> {severity}
      {score != null && <span className="sev-score">{score}</span>}
    </span>
  );
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`status status-${status.toLowerCase()}`}>{status === "INVESTIGATING" ? "Investigating" : status === "NEW" ? "New" : "Closed"}</span>;
}
