package com.threatlens.detection;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WindowsTest {

    @Test
    void oneBurstPerContinuousActivity_notOnePerOverlappingWindow() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 30; i++) evs.add(TestEvents.at(i * 10, EventType.LOGON_FAILURE));
        List<List<SecurityEvent>> bursts = Windows.bursts(evs, Duration.ofMinutes(2), 5, null);
        assertThat(bursts).hasSize(1);
        assertThat(bursts.getFirst()).hasSize(30);
    }

    @Test
    void separatedActivityProducesSeparateBursts() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 5; i++) evs.add(TestEvents.at(i, EventType.LOGON_FAILURE));
        for (int i = 0; i < 5; i++) evs.add(TestEvents.at(3600 + i, EventType.LOGON_FAILURE));
        assertThat(Windows.bursts(evs, Duration.ofMinutes(2), 5, null)).hasSize(2);
    }

    @Test
    void belowThresholdOrTooSpreadOutDoesNotFire() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 10; i++) evs.add(TestEvents.at(i * 60, EventType.LOGON_FAILURE)); // 1/min, max 3 in 2m
        assertThat(Windows.bursts(evs, Duration.ofMinutes(2), 5, null)).isEmpty();
    }

    @Test
    void distinctCountingIgnoresRepeats() {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 50; i++) evs.add(TestEvents.flow(i, "a", "b", 80 + (i % 3)));
        assertThat(Windows.bursts(evs, Duration.ofMinutes(2), 5, SecurityEvent::getDstPort)).isEmpty();
    }
}
