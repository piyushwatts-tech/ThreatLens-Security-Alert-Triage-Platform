package com.threatlens.ml;

import com.threatlens.config.ThreatLensProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/**
 * Client for the Python ML service (scikit-learn anomaly model + LLM summaries).
 * Every call degrades gracefully: detection never fails because ML is down.
 */
@Component
public class MlClient {

    private static final Logger log = LoggerFactory.getLogger(MlClient.class);
    private final RestClient http;

    public MlClient(ThreatLensProperties props) {
        SimpleClientHttpRequestFactory f = new SimpleClientHttpRequestFactory();
        f.setConnectTimeout(2_000);
        f.setReadTimeout(60_000);
        this.http = RestClient.builder().baseUrl(props.mlServiceUrl()).requestFactory(f).build();
    }

    public record ScoreRequest(List<Map<String, Object>> flows) {}
    public record ScoreResponse(List<Double> scores, double threshold, String model) {}
    public record SummaryResponse(String summary, String source) {}
    public record Health(String status, boolean modelLoaded, boolean llmEnabled, String llmModel) {}

    /** Anomaly scores in [0,1] (higher = more anomalous), aligned with the input, or null if unavailable. */
    public ScoreResponse score(List<Map<String, Object>> flows) {
        try {
            return http.post().uri("/score").body(new ScoreRequest(flows)).retrieve().body(ScoreResponse.class);
        } catch (Exception ex) {
            log.warn("ML scoring unavailable: {}", ex.getMessage());
            return null;
        }
    }

    public SummaryResponse summarize(Map<String, Object> alert) {
        try {
            return http.post().uri("/summarize").body(alert).retrieve().body(SummaryResponse.class);
        } catch (Exception ex) {
            log.warn("ML summary unavailable: {}", ex.getMessage());
            return null;
        }
    }

    public Health health() {
        try {
            Map<?, ?> m = http.get().uri("/health").retrieve().body(Map.class);
            return new Health(String.valueOf(m.get("status")), Boolean.TRUE.equals(m.get("model_loaded")),
                    Boolean.TRUE.equals(m.get("llm_enabled")), (String) m.get("llm_model"));
        } catch (Exception ex) {
            return new Health("unreachable", false, false, null);
        }
    }
}
