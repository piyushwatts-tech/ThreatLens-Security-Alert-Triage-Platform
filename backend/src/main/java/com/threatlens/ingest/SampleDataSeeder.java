package com.threatlens.ingest;

import com.threatlens.ml.MlClient;
import com.threatlens.repo.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Loads the bundled sample datasets on first boot when {@code threatlens.seed-dir} is set
 * and the database holds no events. Used by hosted deployments (Render) that have no
 * separate seed job. Waits briefly for the ML service so ML-001 anomaly alerts are produced
 * even when that service is still cold-starting.
 */
@Component
public class SampleDataSeeder {

    private static final Logger log = LoggerFactory.getLogger(SampleDataSeeder.class);

    private final IngestService ingest;
    private final SecurityEventRepository events;
    private final MlClient ml;
    private final String seedDir;
    private final int mlWaitSeconds;

    public SampleDataSeeder(IngestService ingest, SecurityEventRepository events, MlClient ml,
                            @Value("${threatlens.seed-dir:}") String seedDir,
                            @Value("${threatlens.seed-ml-wait-seconds:180}") int mlWaitSeconds) {
        this.ingest = ingest;
        this.events = events;
        this.ml = ml;
        this.seedDir = seedDir;
        this.mlWaitSeconds = mlWaitSeconds;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void seedIfEmpty() {
        if (seedDir == null || seedDir.isBlank()) return;
        if (events.count() > 0) {
            log.info("Seed skipped: database already has events");
            return;
        }
        Path dir = Path.of(seedDir);
        waitForMl();
        try {
            Path csv = dir.resolve("cicids2017_sample.csv");
            if (Files.exists(csv)) {
                try (InputStream in = Files.newInputStream(csv)) {
                    log.info("Seeded network flows: {}", ingest.ingestCicIds(in, 0, true));
                }
            }
            Path win = dir.resolve("windows_security_sample.jsonl");
            if (Files.exists(win)) {
                try (InputStream in = Files.newInputStream(win)) {
                    log.info("Seeded Windows events: {}", ingest.ingestWindows(in, 0, true));
                }
            }
        } catch (Exception ex) {
            log.error("Sample data seed failed", ex);
        }
    }

    private void waitForMl() {
        long deadline = System.currentTimeMillis() + mlWaitSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            if (ml.health().modelLoaded()) return;
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        log.warn("ML service not ready after {}s; seeding without anomaly scores", mlWaitSeconds);
    }
}
