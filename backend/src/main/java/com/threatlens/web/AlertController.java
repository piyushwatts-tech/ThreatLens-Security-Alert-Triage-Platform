package com.threatlens.web;

import com.threatlens.alert.AlertService;
import com.threatlens.alert.Playbooks;
import com.threatlens.alert.SummaryService;
import com.threatlens.domain.*;
import com.threatlens.repo.SecurityEventRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/alerts")
@Tag(name = "Alerts", description = "Alert queue and analyst workflow")
public class AlertController {

    private static final Set<String> SORTABLE = Set.of("firstSeen", "lastSeen", "riskScore", "severity", "status", "eventCount");

    private final AlertService service;
    private final SummaryService summaries;
    private final SecurityEventRepository events;

    public AlertController(AlertService service, SummaryService summaries, SecurityEventRepository events) {
        this.service = service;
        this.summaries = summaries;
        this.events = events;
    }

    public record AlertRow(Long id, String ruleId, String title, Severity severity, int riskScore, AlertStatus status,
                           Resolution resolution, String assignee, String mitreTactic, String mitreTechnique,
                           String mitreTechniqueName, String srcIp, String dstIp, String host, String username,
                           Instant firstSeen, Instant lastSeen, int eventCount, Double anomalyScore) {
        static AlertRow of(Alert a) {
            return new AlertRow(a.getId(), a.getRuleId(), a.getTitle(), a.getSeverity(), a.getRiskScore(), a.getStatus(),
                    a.getResolution(), a.getAssignee(), a.getMitreTactic(), a.getMitreTechnique(),
                    a.getMitreTechniqueName(), a.getSrcIp(), a.getDstIp(), a.getHost(), a.getUsername(),
                    a.getFirstSeen(), a.getLastSeen(), a.getEventCount(), a.getAnomalyScore());
        }
    }

    public record PageOut<T>(List<T> items, long total, int page, int size) {}

    @Operation(summary = "Search alerts with filters, paging and sorting")
    @GetMapping
    public PageOut<AlertRow> list(@RequestParam(required = false) List<AlertStatus> status,
                                  @RequestParam(required = false) List<Severity> severity,
                                  @RequestParam(required = false) String ruleId,
                                  @RequestParam(required = false) String tactic,
                                  @RequestParam(required = false) String assignee,
                                  @RequestParam(required = false) String q,
                                  @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
                                  @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
                                  @RequestParam(defaultValue = "0") int page,
                                  @RequestParam(defaultValue = "25") int size,
                                  @RequestParam(defaultValue = "riskScore") String sort,
                                  @RequestParam(defaultValue = "desc") String dir) {
        String sortField = SORTABLE.contains(sort) ? sort : "riskScore";
        Sort s = Sort.by("asc".equalsIgnoreCase(dir) ? Sort.Direction.ASC : Sort.Direction.DESC, sortField)
                .and(Sort.by(Sort.Direction.DESC, "firstSeen"));
        Page<Alert> p = service.search(new AlertService.AlertFilter(status, severity, ruleId, tactic, assignee, q, from, to),
                PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 200), s));
        return new PageOut<>(p.map(AlertRow::of).getContent(), p.getTotalElements(), p.getNumber(), p.getSize());
    }

    public record EventView(Long id, Instant time, String type, String source, String srcIp, String dstIp,
                            Integer dstPort, String host, String username, String process, String commandLine,
                            Long bytes, Long packets, String datasetLabel) {
        static EventView of(SecurityEvent e) {
            return new EventView(e.getId(), e.getEventTime(), e.getEventType().name(), e.getSource(), e.getSrcIp(),
                    e.getDstIp(), e.getDstPort(), e.getHost(), e.getUsername(), e.getProcess(), e.getCommandLine(),
                    e.getBytes(), e.getPackets(), e.getLabel());
        }
    }

    public record AlertDetail(Alert alert, String mitreUrl, List<String> playbook,
                              List<AlertActivity> activity, List<EventView> events) {}

    @Operation(summary = "Alert detail with evidence events, playbook and audit trail")
    @GetMapping("/{id}")
    public AlertDetail get(@PathVariable Long id) {
        Alert a = service.get(id);
        List<Long> ids = a.getEvidenceEventIds().stream().limit(50).toList();
        List<EventView> ev = events.findAllById(ids).stream()
                .sorted(java.util.Comparator.comparing(SecurityEvent::getEventTime)).map(EventView::of).toList();
        String url = a.getMitreTechnique() == null ? null
                : "https://attack.mitre.org/techniques/" + a.getMitreTechnique().replace('.', '/') + "/";
        return new AlertDetail(a, url, Playbooks.forRule(a.getRuleId()), service.activity(id), ev);
    }

    public record StatusChange(@NotNull AlertStatus status, Resolution resolution, String note, String actor) {}

    @Operation(summary = "Move an alert through NEW -> INVESTIGATING -> CLOSED")
    @PatchMapping("/{id}/status")
    public AlertRow status(@PathVariable Long id, @RequestBody @Valid StatusChange body) {
        return AlertRow.of(service.changeStatus(id, body.status(), body.resolution(), body.note(), body.actor()));
    }

    public record BulkStatusChange(@NotEmpty List<Long> ids, @NotNull AlertStatus status, Resolution resolution,
                                   String note, String actor) {}

    @PostMapping("/bulk/status")
    public Map<String, Integer> bulk(@RequestBody @Valid BulkStatusChange body) {
        return Map.of("updated", service.bulkStatus(body.ids(), body.status(), body.resolution(), body.note(), body.actor()));
    }

    public record Assign(String assignee, String actor) {}

    @PatchMapping("/{id}/assignee")
    public AlertRow assign(@PathVariable Long id, @RequestBody Assign body) {
        return AlertRow.of(service.assign(id, body.assignee(), body.actor()));
    }

    public record Note(@NotNull String note, String actor) {}

    @PostMapping("/{id}/notes")
    public AlertActivity note(@PathVariable Long id, @RequestBody @Valid Note body) {
        return service.addNote(id, body.note(), body.actor());
    }

    @Operation(summary = "(Re)generate the AI triage summary via the ML/LLM service")
    @PostMapping("/{id}/summary")
    public Map<String, String> summary(@PathVariable Long id) {
        Alert a = summaries.regenerate(id);
        return Map.of("summary", a.getSummary(), "source", a.getSummarySource());
    }
}
