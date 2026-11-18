package com.threatlens.domain;

import java.util.Map;
import java.util.Set;

/** Analyst workflow: NEW -> INVESTIGATING -> CLOSED (reopen allowed). */
public enum AlertStatus {
    NEW, INVESTIGATING, CLOSED;

    private static final Map<AlertStatus, Set<AlertStatus>> ALLOWED = Map.of(
            NEW, Set.of(INVESTIGATING, CLOSED),
            INVESTIGATING, Set.of(CLOSED, NEW),
            CLOSED, Set.of(INVESTIGATING));

    public boolean canTransitionTo(AlertStatus next) {
        return ALLOWED.get(this).contains(next);
    }
}
