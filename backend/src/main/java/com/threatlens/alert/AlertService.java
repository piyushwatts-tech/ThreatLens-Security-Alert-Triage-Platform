package com.threatlens.alert;

import com.threatlens.detection.Detection;
import com.threatlens.detection.RiskScorer;
import com.threatlens.domain.*;
import com.threatlens.ml.MlClient;
import com.threatlens.repo.AlertActivityRepository;
import com.threatlens.repo.AlertRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
public class AlertService {

    public static final String SYSTEM_ACTOR = "detection-engine";
    private static final Duration CORRELATION_WINDOW = Duration.ofHours(24);

    private final AlertRepository alerts;
    private final AlertActivityRepository activity;
    private final RiskScorer scorer;
    private final SummaryService summaries;
    private final MlClient ml;

    public AlertService(AlertRepository alerts, AlertActivityRepository activity, RiskScorer scorer,
                        SummaryService summaries, MlClient ml) {
        this.alerts = alerts;
        this.activity = activity;
        this.scorer = scorer;
        this.summaries = summaries;
        this.ml = ml;
    }

    public record NewAlert(Detection detection, Double anomalyScore) {}

    @Transactional
    public int createAlerts(List<NewAlert> fresh) {
        List<Alert> created = new ArrayList<>();
        for (NewAlert n : fresh) {
            Detection d = n.detection();
            Alert a = new Alert();
            a.setFingerprint(d.fingerprint());
            a.setRuleId(d.ruleId());
            a.setTitle(truncate(d.title(), 255));
            a.setDescription(d.description());
            if (d.technique() != null) {
                a.setMitreTechnique(d.technique().id());
                a.setMitreTechniqueName(d.technique().name());
                a.setMitreTactic(d.technique().tactic());
            }
            a.setSrcIp(d.srcIp());
            a.setDstIp(d.dstIp());
            a.setHost(d.host());
            a.setUsername(d.username());
            a.setFirstSeen(d.firstSeen());
            a.setLastSeen(d.lastSeen());
            a.setEventCount(d.events().size());
            a.setEvidenceEventIds(d.events().stream().limit(200).map(SecurityEvent::getId).toList());
            a.setEvidence(new LinkedHashMap<>(d.evidence()));
            a.setAnomalyScore(n.anomalyScore());
            Map<String, Integer> factors = scorer.factors(d, n.anomalyScore());
            a.setScoreFactors(factors);
            applyScore(a);
            created.add(alerts.save(a));
        }
        alerts.flush();

        // Correlation: same entity seen by a *different* rule within 24h raises risk.
        for (Alert a : created) {
            List<Long> related = alerts.findByFirstSeenBetween(
                            a.getFirstSeen().minus(CORRELATION_WINDOW), a.getFirstSeen().plus(CORRELATION_WINDOW)).stream()
                    .filter(o -> !o.getId().equals(a.getId()) && !o.getRuleId().equals(a.getRuleId()) && sharesEntity(a, o))
                    .map(Alert::getId).sorted().limit(20).toList();
            if (!related.isEmpty()) {
                a.getScoreFactors().put("correlation", 10);
                a.getEvidence().put("relatedAlertIds", related);
                applyScore(a);
            }
            a.setSummary(SummaryService.template(a));
            a.setSummarySource("template");
            activity.save(new AlertActivity(a.getId(), SYSTEM_ACTOR, "CREATED", null, AlertStatus.NEW,
                    "Rule " + a.getRuleId() + " fired, risk " + a.getRiskScore()));
        }

        // After commit, ask the LLM for summaries of the alerts that analysts will open first.
        List<Long> llm = created.stream().filter(a -> a.getSeverity().compareTo(Severity.HIGH) >= 0)
                .map(Alert::getId).toList();
        if (!llm.isEmpty() && TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    if (ml.health().llmEnabled()) llm.forEach(summaries::regenerateAsync);
                }
            });
        }
        return created.size();
    }

    private static void applyScore(Alert a) {
        int score = RiskScorer.total(a.getScoreFactors());
        a.setRiskScore(score);
        a.setSeverity(Severity.fromScore(score));
    }

    static boolean sharesEntity(Alert a, Alert b) {
        Set<String> ipsA = new HashSet<>(Arrays.asList(a.getSrcIp(), a.getDstIp()));
        ipsA.remove(null);
        return (b.getSrcIp() != null && ipsA.contains(b.getSrcIp()))
                || (b.getDstIp() != null && ipsA.contains(b.getDstIp()))
                || (a.getHost() != null && a.getHost().equals(b.getHost()))
                || (a.getUsername() != null && a.getUsername().equals(b.getUsername()));
    }

    // ------------------------------------------------------------------ queries

    public record AlertFilter(List<AlertStatus> status, List<Severity> severity, String ruleId, String tactic,
                              String assignee, String q, Instant from, Instant to) {}

    @Transactional(readOnly = true)
    public Page<Alert> search(AlertFilter f, Pageable page) {
        Specification<Alert> spec = (root, query, cb) -> cb.conjunction();
        if (f.status() != null && !f.status().isEmpty()) spec = spec.and((r, q, cb) -> r.get("status").in(f.status()));
        if (f.severity() != null && !f.severity().isEmpty()) spec = spec.and((r, q, cb) -> r.get("severity").in(f.severity()));
        if (notBlank(f.ruleId())) spec = spec.and((r, q, cb) -> cb.equal(r.get("ruleId"), f.ruleId()));
        if (notBlank(f.tactic())) spec = spec.and((r, q, cb) -> cb.equal(r.get("mitreTactic"), f.tactic()));
        if (notBlank(f.assignee())) spec = spec.and((r, q, cb) -> cb.equal(r.get("assignee"), f.assignee()));
        if (f.from() != null) spec = spec.and((r, q, cb) -> cb.greaterThanOrEqualTo(r.get("firstSeen"), f.from()));
        if (f.to() != null) spec = spec.and((r, q, cb) -> cb.lessThanOrEqualTo(r.get("firstSeen"), f.to()));
        if (notBlank(f.q())) {
            String like = "%" + f.q().toLowerCase(Locale.ROOT) + "%";
            spec = spec.and((r, q, cb) -> cb.or(
                    cb.like(cb.lower(r.get("title")), like),
                    cb.like(cb.lower(cb.coalesce(r.get("srcIp"), "")), like),
                    cb.like(cb.lower(cb.coalesce(r.get("dstIp"), "")), like),
                    cb.like(cb.lower(cb.coalesce(r.get("host"), "")), like),
                    cb.like(cb.lower(cb.coalesce(r.get("username"), "")), like),
                    cb.like(cb.lower(cb.coalesce(r.get("mitreTechnique"), "")), like)));
        }
        return alerts.findAll(spec, page);
    }

    @Transactional(readOnly = true)
    public Alert get(Long id) {
        return alerts.findById(id).orElseThrow(() -> new NoSuchElementException("Alert " + id + " not found"));
    }

    @Transactional(readOnly = true)
    public List<AlertActivity> activity(Long id) {
        return activity.findByAlertIdOrderByCreatedAtAsc(id);
    }

    // ---------------------------------------------------------------- workflow

    @Transactional
    public Alert changeStatus(Long id, AlertStatus next, Resolution resolution, String note, String actor) {
        Alert a = get(id);
        AlertStatus prev = a.getStatus();
        if (prev == next) return a;
        if (!prev.canTransitionTo(next)) {
            throw new IllegalStateException("Cannot move alert from " + prev + " to " + next);
        }
        if (next == AlertStatus.CLOSED && resolution == null) {
            throw new IllegalArgumentException("Closing an alert requires a resolution");
        }
        a.setStatus(next);
        a.setResolution(next == AlertStatus.CLOSED ? resolution : null);
        if (next == AlertStatus.INVESTIGATING && a.getAssignee() == null) a.setAssignee(actorOrDefault(actor));
        activity.save(new AlertActivity(id, actorOrDefault(actor), "STATUS_CHANGE", prev, next,
                next == AlertStatus.CLOSED ? joinNote("Resolution: " + resolution, note) : note));
        return a;
    }

    @Transactional
    public Alert assign(Long id, String assignee, String actor) {
        Alert a = get(id);
        a.setAssignee(notBlank(assignee) ? assignee : null);
        activity.save(new AlertActivity(id, actorOrDefault(actor), "ASSIGNED", a.getStatus(), a.getStatus(),
                notBlank(assignee) ? "Assigned to " + assignee : "Unassigned"));
        return a;
    }

    @Transactional
    public AlertActivity addNote(Long id, String note, String actor) {
        if (!notBlank(note)) throw new IllegalArgumentException("Note must not be empty");
        Alert a = get(id);
        return activity.save(new AlertActivity(id, actorOrDefault(actor), "NOTE", a.getStatus(), a.getStatus(), note));
    }

    @Transactional
    public int bulkStatus(List<Long> ids, AlertStatus next, Resolution resolution, String note, String actor) {
        int n = 0;
        for (Long id : ids) {
            Alert a = get(id);
            if (a.getStatus() != next && a.getStatus().canTransitionTo(next)) {
                changeStatus(id, next, resolution, note, actor);
                n++;
            }
        }
        return n;
    }

    private static String actorOrDefault(String actor) {
        return notBlank(actor) ? actor : "analyst";
    }

    private static String joinNote(String a, String b) {
        return notBlank(b) ? a + ". " + b : a;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String truncate(String s, int n) {
        return s == null || s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }
}
