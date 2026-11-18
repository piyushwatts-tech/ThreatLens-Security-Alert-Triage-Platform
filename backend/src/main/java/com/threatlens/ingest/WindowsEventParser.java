package com.threatlens.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Parses Windows event logs exported as JSON lines (the format used by the
 * OTRF Security-Datasets / Mordor project, Winlogbeat and most SIEM exports).
 * A top-level JSON array is accepted too.
 */
public class WindowsEventParser {

    public static final String SOURCE = "WINDOWS";

    private static final Set<String> PRIVILEGED_GROUPS = Set.of(
            "administrators", "domain admins", "enterprise admins", "schema admins",
            "backup operators", "account operators", "remote desktop users");

    private final ObjectMapper mapper = new ObjectMapper();

    public record Result(List<SecurityEvent> events, int skipped) {}

    public Result parse(InputStream in, int maxRows) throws IOException {
        List<SecurityEvent> out = new ArrayList<>();
        int skipped = 0;
        BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        br.mark(1);
        int first = br.read();
        br.reset();
        Iterator<JsonNode> nodes;
        if (first == '[') {
            nodes = mapper.readTree(br).elements();
        } else {
            nodes = br.lines().filter(l -> !l.isBlank()).map(l -> {
                try {
                    return mapper.readTree(l);
                } catch (IOException ex) {
                    return null;
                }
            }).iterator();
        }
        while (nodes.hasNext()) {
            if (maxRows > 0 && out.size() >= maxRows) break;
            JsonNode n = nodes.next();
            SecurityEvent e = n == null ? null : toEvent(n);
            if (e == null) skipped++;
            else out.add(e);
        }
        return new Result(out, skipped);
    }

    SecurityEvent toEvent(JsonNode n) {
        int id = n.path("EventID").asInt(-1);
        String channel = text(n, "Channel");
        boolean sysmon = channel != null && channel.toLowerCase(Locale.ROOT).contains("sysmon");
        EventType type = classify(id, sysmon);
        if (type == EventType.OTHER) return null;
        Instant ts = time(n);
        if (ts == null) return null;

        SecurityEvent e = SecurityEvent.of(SOURCE, type, ts);
        e.setHost(shortHost(firstText(n, "Hostname", "Computer", "host.name")));
        e.setSrcIp(cleanIp(firstText(n, "IpAddress", "SourceIp", "SourceAddress")));
        switch (type) {
            case LOGON_SUCCESS, LOGON_FAILURE -> e.setUsername(text(n, "TargetUserName"));
            case PROCESS_CREATE -> {
                e.setUsername(firstText(n, "SubjectUserName", "User"));
                e.setProcess(firstText(n, "NewProcessName", "Image"));
                e.setParentProcess(firstText(n, "ParentProcessName", "ParentImage"));
                e.setCommandLine(text(n, "CommandLine"));
            }
            case ACCOUNT_CREATED -> e.setUsername(text(n, "TargetUserName"));
            case GROUP_MEMBER_ADDED -> e.setUsername(memberName(firstText(n, "MemberName", "MemberSid")));
            case LOG_CLEARED -> e.setUsername(text(n, "SubjectUserName"));
            default -> { }
        }
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("EventID", id);
        for (String f : List.of("LogonType", "Status", "SubStatus", "SubjectUserName", "TargetDomainName",
                "WorkstationName", "AuthenticationPackageName", "MemberSid")) {
            String v = text(n, f);
            if (v != null) attrs.put(f, v);
        }
        if (type == EventType.GROUP_MEMBER_ADDED) {
            String group = text(n, "TargetUserName");
            attrs.put("GroupName", group);
            attrs.put("PrivilegedGroup", group != null && PRIVILEGED_GROUPS.contains(group.toLowerCase(Locale.ROOT)));
        }
        e.setAttributes(attrs);
        return e;
    }

    static EventType classify(int id, boolean sysmon) {
        if (sysmon) return id == 1 ? EventType.PROCESS_CREATE : EventType.OTHER;
        return switch (id) {
            case 4624 -> EventType.LOGON_SUCCESS;
            case 4625 -> EventType.LOGON_FAILURE;
            case 4688 -> EventType.PROCESS_CREATE;
            case 4720 -> EventType.ACCOUNT_CREATED;
            case 4728, 4732, 4756 -> EventType.GROUP_MEMBER_ADDED;
            case 1102 -> EventType.LOG_CLEARED;
            default -> EventType.OTHER;
        };
    }

    private static Instant time(JsonNode n) {
        String raw = firstText(n, "@timestamp", "TimeCreated", "EventTime", "UtcTime");
        if (raw == null) return null;
        try {
            return Instant.parse(raw);
        } catch (Exception ignored) {
            // fall through to other formats
        }
        try {
            String norm = raw.replace('T', ' ');
            if (norm.length() > 19) norm = norm.substring(0, 19);
            return LocalDateTime.parse(norm, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")).toInstant(ZoneOffset.UTC);
        } catch (Exception ex) {
            return null;
        }
    }

    private static String memberName(String raw) {
        if (raw == null) return null;
        // "CN=svc_backup2,OU=..." -> svc_backup2
        if (raw.startsWith("CN=")) {
            int comma = raw.indexOf(',');
            return raw.substring(3, comma > 0 ? comma : raw.length());
        }
        return raw;
    }

    static String shortHost(String fqdn) {
        if (fqdn == null) return null;
        int dot = fqdn.indexOf('.');
        return (dot > 0 ? fqdn.substring(0, dot) : fqdn).toUpperCase(Locale.ROOT);
    }

    private static String cleanIp(String ip) {
        if (ip == null || ip.isBlank() || ip.equals("-") || ip.equals("::1") || ip.equals("127.0.0.1")) return null;
        return ip.startsWith("::ffff:") ? ip.substring(7) : ip;
    }

    private static String firstText(JsonNode n, String... fields) {
        for (String f : fields) {
            String v = text(n, f);
            if (v != null) return v;
        }
        return null;
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = field.contains(".") ? n.at("/" + field.replace('.', '/')) : n.get(field);
        if (v == null || v.isNull() || v.isMissingNode()) return null;
        String s = v.asText();
        return s.isBlank() || s.equals("-") ? null : s;
    }
}
