package com.threatlens.ingest;

import com.threatlens.detection.DetectionEngine;
import com.threatlens.domain.SecurityEvent;
import com.threatlens.repo.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);
    private static final int CHUNK = 1_000;

    private final SecurityEventRepository repo;
    private final DetectionEngine engine;

    public IngestService(SecurityEventRepository repo, DetectionEngine engine) {
        this.repo = repo;
        this.engine = engine;
    }

    public record IngestResult(String batchId, String source, int parsed, int skipped, int stored,
                               long timeShiftSeconds, DetectionEngine.RunResult detection) {}

    public IngestResult ingestCicIds(InputStream in, int maxRows, boolean rebase) throws IOException {
        CicIdsCsvParser.Result r = new CicIdsCsvParser().parse(in, maxRows);
        return store(CicIdsCsvParser.SOURCE, r.events(), r.skipped(), rebase);
    }

    public IngestResult ingestWindows(InputStream in, int maxRows, boolean rebase) throws IOException {
        WindowsEventParser.Result r = new WindowsEventParser().parse(in, maxRows);
        return store(WindowsEventParser.SOURCE, r.events(), r.skipped(), rebase);
    }

    public IngestResult ingestEvents(List<SecurityEvent> events) {
        return store("API", events, 0, false);
    }

    /**
     * Persists a batch and immediately runs detection over its time range.
     * {@code rebase} shifts historic datasets (2017/2020) so the newest event is
     * "a few minutes ago", which makes the dashboard timelines meaningful in a demo.
     */
    IngestResult store(String source, List<SecurityEvent> events, int skipped, boolean rebase) {
        String batch = UUID.randomUUID().toString();
        if (events.isEmpty()) {
            return new IngestResult(batch, source, 0, skipped, 0, 0, null);
        }
        long shift = 0;
        if (rebase) {
            Instant max = events.stream().map(SecurityEvent::getEventTime).max(Comparator.naturalOrder()).orElseThrow();
            shift = Duration.between(max, Instant.now().minus(Duration.ofMinutes(5))).toSeconds();
        }
        for (SecurityEvent e : events) {
            e.setBatchId(batch);
            if (e.getSource() == null) e.setSource(source);
            if (shift != 0) e.setEventTime(e.getEventTime().plusSeconds(shift));
        }
        for (int i = 0; i < events.size(); i += CHUNK) {
            repo.saveAll(events.subList(i, Math.min(events.size(), i + CHUNK)));
        }
        Instant min = events.stream().map(SecurityEvent::getEventTime).min(Comparator.naturalOrder()).orElseThrow();
        Instant max = events.stream().map(SecurityEvent::getEventTime).max(Comparator.naturalOrder()).orElseThrow();
        log.info("Stored {} {} events (batch {}), running detection", events.size(), source, batch);
        DetectionEngine.RunResult det = engine.runForRange(min, max);
        return new IngestResult(batch, source, events.size() + skipped, skipped, events.size(), shift, det);
    }
}
