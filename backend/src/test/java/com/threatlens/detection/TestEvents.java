package com.threatlens.detection;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;

import java.time.Instant;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicLong;

public final class TestEvents {
    private static final AtomicLong IDS = new AtomicLong();
    public static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private TestEvents() {}

    public static SecurityEvent at(int secondsAfterT0, EventType type) {
        SecurityEvent e = SecurityEvent.of("TEST", type, T0.plusSeconds(secondsAfterT0));
        e.setId(IDS.incrementAndGet());
        e.setAttributes(new HashMap<>());
        return e;
    }

    public static SecurityEvent flow(int s, String src, String dst, int port) {
        SecurityEvent e = at(s, EventType.NETWORK_FLOW);
        e.setSrcIp(src);
        e.setDstIp(dst);
        e.setDstPort(port);
        e.setPackets(2L);
        return e;
    }

    public static SecurityEvent logon(int s, boolean ok, String ip, String user, String host) {
        SecurityEvent e = at(s, ok ? EventType.LOGON_SUCCESS : EventType.LOGON_FAILURE);
        e.setSrcIp(ip);
        e.setUsername(user);
        e.setHost(host);
        e.getAttributes().put("LogonType", "3");
        return e;
    }
}
