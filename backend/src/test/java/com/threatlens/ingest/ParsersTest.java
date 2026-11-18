package com.threatlens.ingest;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ParsersTest {

    private static final Path SAMPLE = Path.of("..", "data", "sample");

    @Test
    void parsesRealCicHeaderQuirks_infinityAndTimestamps() throws Exception {
        String csv = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
                + " Total Fwd Packets, Total Backward Packets,Flow Bytes/s, Label\n"
                + "x,172.16.0.1,40000,192.168.10.50,22,6,7/7/2017 3:30,10,1,1,Infinity,SSH-Patator\n"
                + "x,172.16.0.1,40001,192.168.10.50,22,6,7/7/2017 15:30:05,10,1,1,NaN,SSH-Patator\n";
        var r = new CicIdsCsvParser().parse(new ByteArrayInputStream(csv.getBytes(StandardCharsets.UTF_8)), 0);
        assertThat(r.events()).hasSize(2);
        SecurityEvent e = r.events().getFirst();
        assertThat(e.getSrcIp()).isEqualTo("172.16.0.1");
        assertThat(e.getDstPort()).isEqualTo(22);
        assertThat(e.getEventTime()).isEqualTo(Instant.parse("2017-07-07T03:30:00Z"));
        assertThat(e.getAttributes()).doesNotContainKey("Flow Bytes/s"); // Infinity dropped
        assertThat(e.getPackets()).isEqualTo(2);
    }

    @Test
    void rejectsNonCicCsv() {
        assertThatThrownBy(() -> new CicIdsCsvParser().parse(new ByteArrayInputStream("a,b\n1,2\n".getBytes()), 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sampleCicFileParsesCompletely() throws Exception {
        try (InputStream in = new FileInputStream(SAMPLE.resolve("cicids2017_sample.csv").toFile())) {
            var r = new CicIdsCsvParser().parse(in, 0);
            assertThat(r.skipped()).isZero();
            assertThat(r.events()).hasSizeGreaterThan(4000);
        }
    }

    @Test
    void windowsSampleMapsEventIdsToTypes() throws Exception {
        try (InputStream in = new FileInputStream(SAMPLE.resolve("windows_security_sample.jsonl").toFile())) {
            var r = new WindowsEventParser().parse(in, 0);
            Map<EventType, Long> byType = r.events().stream()
                    .collect(Collectors.groupingBy(SecurityEvent::getEventType, Collectors.counting()));
            assertThat(byType).containsKeys(EventType.LOGON_SUCCESS, EventType.LOGON_FAILURE, EventType.PROCESS_CREATE,
                    EventType.ACCOUNT_CREATED, EventType.GROUP_MEMBER_ADDED, EventType.LOG_CLEARED);
        }
    }

    @Test
    void parsesSysmonAndJsonArray() throws Exception {
        String json = """
                [{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Hostname":"wks1.corp.local",
                  "@timestamp":"2020-09-21T10:00:00.000Z","Image":"C:\\\\x\\\\powershell.exe","CommandLine":"powershell -enc AAAA",
                  "ParentImage":"C:\\\\x\\\\winword.exe","User":"CORP\\\\bob"},
                 {"EventID":4624,"Hostname":"dc01","TimeCreated":"2020-09-21 10:00:01","TargetUserName":"bob","IpAddress":"::ffff:10.1.1.1"}]
                """;
        var r = new WindowsEventParser().parse(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)), 0);
        assertThat(r.events()).hasSize(2);
        assertThat(r.events().get(0).getEventType()).isEqualTo(EventType.PROCESS_CREATE);
        assertThat(r.events().get(0).getHost()).isEqualTo("WKS1");
        assertThat(r.events().get(1).getSrcIp()).isEqualTo("10.1.1.1");
    }
}
