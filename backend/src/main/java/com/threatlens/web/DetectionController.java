package com.threatlens.web;

import com.threatlens.detection.DetectionEngine;
import com.threatlens.detection.DetectionRule;
import com.threatlens.ml.MlClient;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api")
@Tag(name = "Detection", description = "Rule catalog and on-demand detection runs")
public class DetectionController {

    private final DetectionEngine engine;
    private final MlClient ml;

    public DetectionController(DetectionEngine engine, MlClient ml) {
        this.engine = engine;
        this.ml = ml;
    }

    public record RuleView(String id, String name, String description, String logic, int baseScore,
                           String mitreTechnique, String mitreTechniqueName, String mitreTactic, String mitreUrl) {
        static RuleView of(DetectionRule r) {
            return new RuleView(r.id(), r.name(), r.description(), r.logic(), r.baseScore(), r.technique().id(),
                    r.technique().name(), r.technique().tactic(), r.technique().url());
        }
    }

    @GetMapping("/rules")
    public List<RuleView> rules() {
        return engine.catalog().stream().map(RuleView::of).toList();
    }

    @Operation(summary = "Run all rules over a time range (default: all stored events). Idempotent.")
    @PostMapping("/detections/run")
    public DetectionEngine.RunResult run(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        if (from == null || to == null) return engine.runAll();
        return engine.run(from, to);
    }

    @GetMapping("/ml/health")
    public MlClient.Health mlHealth() {
        return ml.health();
    }
}
