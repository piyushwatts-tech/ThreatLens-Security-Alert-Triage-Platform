package com.threatlens.web;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import com.threatlens.ingest.IngestService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ingest")
@Tag(name = "Ingestion", description = "Load telemetry; detection runs automatically on each batch")
public class IngestController {

    private final IngestService ingest;

    public IngestController(IngestService ingest) {
        this.ingest = ingest;
    }

    @Operation(summary = "Upload a CIC-IDS2017 TrafficLabelling CSV")
    @PostMapping(value = "/cicids", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public IngestService.IngestResult cicids(@RequestParam("file") MultipartFile file,
                                             @RequestParam(defaultValue = "0") int maxRows,
                                             @RequestParam(defaultValue = "false") boolean rebaseTime) throws IOException {
        try (InputStream in = file.getInputStream()) {
            return ingest.ingestCicIds(in, maxRows, rebaseTime);
        }
    }

    @Operation(summary = "Upload Windows Security / Sysmon events as JSON lines (OTRF Security-Datasets format)")
    @PostMapping(value = "/windows", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public IngestService.IngestResult windows(@RequestParam("file") MultipartFile file,
                                              @RequestParam(defaultValue = "0") int maxRows,
                                              @RequestParam(defaultValue = "false") boolean rebaseTime) throws IOException {
        try (InputStream in = file.getInputStream()) {
            return ingest.ingestWindows(in, maxRows, rebaseTime);
        }
    }

    public record EventIn(String source, @NotNull EventType eventType, @NotNull Instant timestamp,
                          String srcIp, String dstIp, Integer dstPort, Integer protocol, String host,
                          String username, String process, String parentProcess, String commandLine,
                          Long bytes, Long packets, Map<String, Object> attributes) {
        SecurityEvent toEntity() {
            SecurityEvent e = SecurityEvent.of(source == null ? "API" : source, eventType, timestamp);
            e.setSrcIp(srcIp); e.setDstIp(dstIp); e.setDstPort(dstPort); e.setProtocol(protocol);
            e.setHost(host); e.setUsername(username); e.setProcess(process); e.setParentProcess(parentProcess);
            e.setCommandLine(commandLine); e.setBytes(bytes); e.setPackets(packets);
            if (attributes != null) e.setAttributes(new java.util.HashMap<>(attributes));
            return e;
        }
    }

    @Operation(summary = "Push normalized events as JSON (log shippers, custom integrations)")
    @PostMapping("/events")
    public IngestService.IngestResult events(@RequestBody @Valid @NotEmpty List<@Valid EventIn> events) {
        return ingest.ingestEvents(events.stream().map(EventIn::toEntity).toList());
    }
}
