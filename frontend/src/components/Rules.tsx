import { useEffect, useState } from "react";
import { api } from "../api";
import type { Rule } from "../types";

export function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [ml, setMl] = useState<{ modelLoaded: boolean; llmEnabled: boolean; llmModel: string | null; status: string } | null>(null);
  useEffect(() => {
    api.rules().then(setRules).catch(() => {});
    api.mlHealth().then(setMl).catch(() => {});
  }, []);

  return (
    <div className="rules">
      {ml && (
        <div className="card ml-status">
          <b>ML service:</b> {ml.status === "ok" ? "online" : ml.status} · anomaly model {ml.modelLoaded ? "loaded" : "not trained"} ·
          LLM summaries {ml.llmEnabled ? `on (${ml.llmModel})` : "off (template summaries; set ANTHROPIC_API_KEY to enable)"}
        </div>
      )}
      <div className="table-wrap">
        <table className="alerts">
          <thead>
            <tr><th>Rule</th><th>Logic</th><th>ATT&CK</th><th className="num">Base risk</th></tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td>
                  <div className="title"><span className="mono">{r.id}</span> {r.name}</div>
                  <div className="sub">{r.description}</div>
                </td>
                <td className="mono small wrap">{r.logic}</td>
                <td>
                  <a href={r.mitreUrl} target="_blank" rel="noreferrer" className="mono">{r.mitreTechnique}</a>
                  <div className="sub">{r.mitreTactic}</div>
                </td>
                <td className="num">{r.baseScore}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
