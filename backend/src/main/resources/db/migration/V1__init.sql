-- Normalized security telemetry from every source (network flows, Windows events, ...)
CREATE SEQUENCE security_event_seq INCREMENT BY 500;
CREATE TABLE security_event (
    id             BIGINT PRIMARY KEY,
    batch_id       VARCHAR(36)  NOT NULL,
    source         VARCHAR(32)  NOT NULL,          -- CICIDS2017 | WINDOWS | API
    event_type     VARCHAR(32)  NOT NULL,          -- NETWORK_FLOW | LOGON_FAILURE | ...
    event_time     TIMESTAMPTZ  NOT NULL,
    src_ip         VARCHAR(64),
    dst_ip         VARCHAR(64),
    dst_port       INTEGER,
    protocol       INTEGER,
    host           VARCHAR(255),
    username       VARCHAR(255),
    process        TEXT,
    parent_process TEXT,
    command_line   TEXT,
    bytes          BIGINT,
    packets        BIGINT,
    duration_us    BIGINT,
    label          VARCHAR(64),                     -- dataset ground truth, never used by rules
    attributes     JSONB
);
CREATE INDEX idx_event_type_time ON security_event (event_type, event_time);
CREATE INDEX idx_event_batch ON security_event (batch_id);
CREATE INDEX idx_event_src_ip ON security_event (src_ip);

CREATE SEQUENCE alert_seq INCREMENT BY 50;
CREATE TABLE alert (
    id                BIGINT PRIMARY KEY,
    fingerprint       VARCHAR(255) NOT NULL UNIQUE, -- rule|entity|burst-start, makes detection idempotent
    rule_id           VARCHAR(32)  NOT NULL,
    title             VARCHAR(255) NOT NULL,
    description       TEXT,
    severity          VARCHAR(16)  NOT NULL,
    risk_score        INTEGER      NOT NULL,
    score_factors     JSONB,
    status            VARCHAR(16)  NOT NULL,
    resolution        VARCHAR(32),
    assignee          VARCHAR(128),
    mitre_tactic      VARCHAR(64),
    mitre_technique   VARCHAR(16),
    mitre_technique_name VARCHAR(128),
    src_ip            VARCHAR(64),
    dst_ip            VARCHAR(64),
    host              VARCHAR(255),
    username          VARCHAR(255),
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    event_count       INTEGER NOT NULL,
    evidence_event_ids JSONB,
    evidence          JSONB,
    anomaly_score     DOUBLE PRECISION,
    summary           TEXT,
    summary_source    VARCHAR(32),
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_alert_status ON alert (status);
CREATE INDEX idx_alert_severity ON alert (severity);
CREATE INDEX idx_alert_first_seen ON alert (first_seen);

-- Audit trail: every status change, assignment and note
CREATE SEQUENCE alert_activity_seq INCREMENT BY 50;
CREATE TABLE alert_activity (
    id          BIGINT PRIMARY KEY,
    alert_id    BIGINT NOT NULL REFERENCES alert(id) ON DELETE CASCADE,
    actor       VARCHAR(128) NOT NULL,
    action      VARCHAR(32)  NOT NULL,
    from_status VARCHAR(16),
    to_status   VARCHAR(16),
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_activity_alert ON alert_activity (alert_id);
