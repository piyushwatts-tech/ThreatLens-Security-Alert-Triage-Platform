package com.threatlens.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Entity
@Table(name = "security_event")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "event_seq")
    @SequenceGenerator(name = "event_seq", sequenceName = "security_event_seq", allocationSize = 500)
    private Long id;

    private String batchId;
    private String source;

    @Enumerated(EnumType.STRING)
    private EventType eventType;

    private Instant eventTime;
    private String srcIp;
    private String dstIp;
    private Integer dstPort;
    private Integer protocol;
    private String host;
    private String username;
    private String process;
    private String parentProcess;
    private String commandLine;
    private Long bytes;
    private Long packets;
    private Long durationUs;
    private String label;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> attributes = new HashMap<>();

    public SecurityEvent() {}

    public static SecurityEvent of(String source, EventType type, Instant time) {
        SecurityEvent e = new SecurityEvent();
        e.source = source;
        e.eventType = type;
        e.eventTime = time;
        return e;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getBatchId() { return batchId; }
    public void setBatchId(String batchId) { this.batchId = batchId; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public EventType getEventType() { return eventType; }
    public void setEventType(EventType eventType) { this.eventType = eventType; }
    public Instant getEventTime() { return eventTime; }
    public void setEventTime(Instant eventTime) { this.eventTime = eventTime; }
    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }
    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }
    public Integer getDstPort() { return dstPort; }
    public void setDstPort(Integer dstPort) { this.dstPort = dstPort; }
    public Integer getProtocol() { return protocol; }
    public void setProtocol(Integer protocol) { this.protocol = protocol; }
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getProcess() { return process; }
    public void setProcess(String process) { this.process = process; }
    public String getParentProcess() { return parentProcess; }
    public void setParentProcess(String parentProcess) { this.parentProcess = parentProcess; }
    public String getCommandLine() { return commandLine; }
    public void setCommandLine(String commandLine) { this.commandLine = commandLine; }
    public Long getBytes() { return bytes; }
    public void setBytes(Long bytes) { this.bytes = bytes; }
    public Long getPackets() { return packets; }
    public void setPackets(Long packets) { this.packets = packets; }
    public Long getDurationUs() { return durationUs; }
    public void setDurationUs(Long durationUs) { this.durationUs = durationUs; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public Map<String, Object> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes; }
}
