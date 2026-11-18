package com.threatlens.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "alert")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "alert_seq_gen")
    @SequenceGenerator(name = "alert_seq_gen", sequenceName = "alert_seq", allocationSize = 50)
    private Long id;

    private String fingerprint;
    private String ruleId;
    private String title;
    private String description;

    @Enumerated(EnumType.STRING)
    private Severity severity;
    private int riskScore;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Integer> scoreFactors = new LinkedHashMap<>();

    @Enumerated(EnumType.STRING)
    private AlertStatus status = AlertStatus.NEW;

    @Enumerated(EnumType.STRING)
    private Resolution resolution;
    private String assignee;

    private String mitreTactic;
    private String mitreTechnique;
    private String mitreTechniqueName;

    private String srcIp;
    private String dstIp;
    private String host;
    private String username;

    private Instant firstSeen;
    private Instant lastSeen;
    private int eventCount;

    @JdbcTypeCode(SqlTypes.JSON)
    private List<Long> evidenceEventIds = new ArrayList<>();

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> evidence = new LinkedHashMap<>();

    private Double anomalyScore;
    private String summary;
    private String summarySource;

    private Instant createdAt;
    private Instant updatedAt;

    @PrePersist
    void prePersist() {
        createdAt = updatedAt = Instant.now();
    }

    @PreUpdate
    void preUpdate() {
        updatedAt = Instant.now();
    }

    public Long getId() { return id; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public Map<String, Integer> getScoreFactors() { return scoreFactors; }
    public void setScoreFactors(Map<String, Integer> scoreFactors) { this.scoreFactors = scoreFactors; }
    public AlertStatus getStatus() { return status; }
    public void setStatus(AlertStatus status) { this.status = status; }
    public Resolution getResolution() { return resolution; }
    public void setResolution(Resolution resolution) { this.resolution = resolution; }
    public String getAssignee() { return assignee; }
    public void setAssignee(String assignee) { this.assignee = assignee; }
    public String getMitreTactic() { return mitreTactic; }
    public void setMitreTactic(String mitreTactic) { this.mitreTactic = mitreTactic; }
    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }
    public String getMitreTechniqueName() { return mitreTechniqueName; }
    public void setMitreTechniqueName(String mitreTechniqueName) { this.mitreTechniqueName = mitreTechniqueName; }
    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }
    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
    public int getEventCount() { return eventCount; }
    public void setEventCount(int eventCount) { this.eventCount = eventCount; }
    public List<Long> getEvidenceEventIds() { return evidenceEventIds; }
    public void setEvidenceEventIds(List<Long> evidenceEventIds) { this.evidenceEventIds = evidenceEventIds; }
    public Map<String, Object> getEvidence() { return evidence; }
    public void setEvidence(Map<String, Object> evidence) { this.evidence = evidence; }
    public Double getAnomalyScore() { return anomalyScore; }
    public void setAnomalyScore(Double anomalyScore) { this.anomalyScore = anomalyScore; }
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    public String getSummarySource() { return summarySource; }
    public void setSummarySource(String summarySource) { this.summarySource = summarySource; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
