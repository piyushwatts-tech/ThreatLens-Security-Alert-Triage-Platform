package com.threatlens.ingest;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

/**
 * Parses CIC-IDS2017 "GeneratedLabelledFlows" CSVs (CICFlowMeter output).
 * Handles the quirks of the real files: header names with leading spaces,
 * "Infinity"/"NaN" values and several timestamp formats.
 */
public class CicIdsCsvParser {

    public static final String SOURCE = "CICIDS2017";

    private static final List<DateTimeFormatter> TS_FORMATS = List.of(
            DateTimeFormatter.ofPattern("d/M/yyyy H:mm:ss"),
            DateTimeFormatter.ofPattern("d/M/yyyy H:mm"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd H:mm:ss.SSSSSS"));

    /** Columns that are identity/metadata rather than numeric flow features. */
    private static final Set<String> NON_FEATURES = Set.of(
            "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "Timestamp", "Label");

    public record Result(List<SecurityEvent> events, int skipped) {}

    public Result parse(InputStream in, int maxRows) throws IOException {
        Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
        CSVFormat fmt = CSVFormat.DEFAULT.builder()
                .setHeader().setSkipHeaderRecord(true).setTrim(true)
                .setIgnoreEmptyLines(true).setAllowMissingColumnNames(true).build();
        List<SecurityEvent> events = new ArrayList<>();
        int skipped = 0;
        try (CSVParser parser = CSVParser.parse(reader, fmt)) {
            // header -> index, keyed by trimmed name (real files have " Source IP" etc.)
            Map<String, Integer> idx = new HashMap<>();
            parser.getHeaderMap().forEach((k, v) -> idx.putIfAbsent(k.trim(), v));
            require(idx, "Source IP", "Destination IP", "Destination Port", "Timestamp");
            for (CSVRecord r : parser) {
                if (maxRows > 0 && events.size() >= maxRows) break;
                try {
                    events.add(toEvent(r, idx));
                } catch (RuntimeException ex) {
                    skipped++;
                }
            }
        }
        return new Result(events, skipped);
    }

    private static void require(Map<String, Integer> idx, String... cols) {
        for (String c : cols) {
            if (!idx.containsKey(c)) {
                throw new IllegalArgumentException("Not a CIC-IDS2017 TrafficLabelling CSV: missing column '" + c + "'");
            }
        }
    }

    private SecurityEvent toEvent(CSVRecord r, Map<String, Integer> idx) {
        SecurityEvent e = SecurityEvent.of(SOURCE, EventType.NETWORK_FLOW, parseTime(get(r, idx, "Timestamp")));
        e.setSrcIp(get(r, idx, "Source IP"));
        e.setDstIp(get(r, idx, "Destination IP"));
        e.setDstPort(intOrNull(get(r, idx, "Destination Port")));
        e.setProtocol(intOrNull(get(r, idx, "Protocol")));
        e.setLabel(get(r, idx, "Label"));

        Map<String, Object> attrs = new LinkedHashMap<>();
        Integer srcPort = intOrNull(get(r, idx, "Source Port"));
        if (srcPort != null) attrs.put("Source Port", srcPort);
        for (Map.Entry<String, Integer> col : idx.entrySet()) {
            if (NON_FEATURES.contains(col.getKey()) || col.getValue() >= r.size()) continue;
            Double d = doubleOrNull(r.get(col.getValue()));
            if (d != null) attrs.put(col.getKey(), d);
        }
        e.setAttributes(attrs);
        e.setDurationUs(longOf(attrs.get("Flow Duration")));
        e.setPackets(sum(attrs, "Total Fwd Packets", "Total Backward Packets"));
        e.setBytes(sum(attrs, "Total Length of Fwd Packets", "Total Length of Bwd Packets"));
        return e;
    }

    static Instant parseTime(String raw) {
        for (DateTimeFormatter f : TS_FORMATS) {
            try {
                return LocalDateTime.parse(raw, f).toInstant(ZoneOffset.UTC);
            } catch (DateTimeParseException ignored) {
                // try next format
            }
        }
        throw new IllegalArgumentException("Unparseable timestamp: " + raw);
    }

    private static String get(CSVRecord r, Map<String, Integer> idx, String col) {
        Integer i = idx.get(col);
        return i == null || i >= r.size() ? null : r.get(i);
    }

    private static Integer intOrNull(String s) {
        Double d = doubleOrNull(s);
        return d == null ? null : d.intValue();
    }

    private static Double doubleOrNull(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            double d = Double.parseDouble(s);
            return Double.isFinite(d) ? d : null;   // real data contains Infinity / NaN
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static Long longOf(Object o) {
        return o instanceof Number n ? n.longValue() : null;
    }

    private static Long sum(Map<String, Object> attrs, String a, String b) {
        Long x = longOf(attrs.get(a)), y = longOf(attrs.get(b));
        return x == null && y == null ? null : (x == null ? 0 : x) + (y == null ? 0 : y);
    }
}
