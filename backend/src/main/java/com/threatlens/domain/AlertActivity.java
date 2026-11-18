package com.threatlens.domain;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "alert_activity")
public class AlertActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "activity_seq_gen")
    @SequenceGenerator(name = "activity_seq_gen", sequenceName = "alert_activity_seq", allocationSize = 50)
    private Long id;

    private Long alertId;
    private String actor;
    private String action;

    @Enumerated(EnumType.STRING)
    private AlertStatus fromStatus;

    @Enumerated(EnumType.STRING)
    private AlertStatus toStatus;

    private String note;
    private Instant createdAt = Instant.now();

    public AlertActivity() {}

    public AlertActivity(Long alertId, String actor, String action, AlertStatus from, AlertStatus to, String note) {
        this.alertId = alertId;
        this.actor = actor;
        this.action = action;
        this.fromStatus = from;
        this.toStatus = to;
        this.note = note;
    }

    public Long getId() { return id; }
    public Long getAlertId() { return alertId; }
    public String getActor() { return actor; }
    public String getAction() { return action; }
    public AlertStatus getFromStatus() { return fromStatus; }
    public AlertStatus getToStatus() { return toStatus; }
    public String getNote() { return note; }
    public Instant getCreatedAt() { return createdAt; }
}
