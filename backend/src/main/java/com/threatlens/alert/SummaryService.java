package com.threatlens.alert;

import com.threatlens.domain.Alert;
import com.threatlens.ml.MlClient;
import com.threatlens.repo.AlertRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builds the analyst-facing summary for an alert. A deterministic template is
 * always available; when the ML service has an LLM configured, it replaces the
 * template with a model-written triage summary.
 */
@Service
public class SummaryService {

    private final MlClient ml;
    private final AlertRepository alerts;

    public SummaryService(MlClient ml, AlertRepository alerts) {
        this.ml = ml;
        this.alerts = alerts;
    }

    public static String template(Alert a) {
        String drivers = a.getScoreFactors().entrySet().stream()
                .filter(e -> !e.getKey().equals("base"))
                .map(e -> e.getKey() + " +" + e.getValue()).collect(Collectors.joining(", "));
        StringBuilder sb = new StringBuilder();
        sb.append(a.getDescription()).append("\n\n");
        if (a.getMitreTechnique() != null) {
            sb.append("ATT&CK: ").append(a.getMitreTechnique()).append(" ").append(a.getMitreTechniqueName())
                    .append(" (").append(a.getMitreTactic()).append(").\n");
        }
        sb.append("Risk ").append(a.getRiskScore()).append("/100 (").append(a.getSeverity()).append(")")
                .append(drivers.isEmpty() ? "" : ", raised by " + drivers).append(".");
        if (a.getAnomalyScore() != null) {
            sb.append(" ML anomaly score ").append(String.format("%.2f", a.getAnomalyScore())).append(".");
        }
        sb.append("\n\nNext steps:\n");
        Playbooks.forRule(a.getRuleId()).forEach(s -> sb.append("- ").append(s).append("\n"));
        return sb.toString().trim();
    }

    public static Map<String, Object> llmPayload(Alert a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId());
        m.put("rule_id", a.getRuleId());
        m.put("title", a.getTitle());
        m.put("description", a.getDescription());
        m.put("severity", a.getSeverity().name());
        m.put("risk_score", a.getRiskScore());
        m.put("score_factors", a.getScoreFactors());
        m.put("mitre", a.getMitreTechnique() == null ? null
                : a.getMitreTechnique() + " " + a.getMitreTechniqueName() + " / " + a.getMitreTactic());
        m.put("entities", Map.of(
                "src_ip", String.valueOf(a.getSrcIp()), "dst_ip", String.valueOf(a.getDstIp()),
                "host", String.valueOf(a.getHost()), "user", String.valueOf(a.getUsername())));
        m.put("first_seen", String.valueOf(a.getFirstSeen()));
        m.put("last_seen", String.valueOf(a.getLastSeen()));
        m.put("event_count", a.getEventCount());
        m.put("anomaly_score", a.getAnomalyScore());
        m.put("evidence", a.getEvidence());
        m.put("playbook", Playbooks.forRule(a.getRuleId()));
        return m;
    }

    /** Regenerates the summary via the ML/LLM service; keeps the template if that fails. */
    @Transactional
    public Alert regenerate(Long alertId) {
        Alert a = alerts.findById(alertId).orElseThrow();
        MlClient.SummaryResponse r = ml.summarize(llmPayload(a));
        if (r != null && r.summary() != null && !r.summary().isBlank()) {
            a.setSummary(r.summary());
            a.setSummarySource(r.source());
        } else if (a.getSummary() == null) {
            a.setSummary(template(a));
            a.setSummarySource("template");
        }
        return a;
    }

    @Async
    public void regenerateAsync(Long alertId) {
        regenerate(alertId);
    }
}
