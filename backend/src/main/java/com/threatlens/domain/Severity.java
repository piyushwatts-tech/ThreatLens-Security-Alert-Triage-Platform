package com.threatlens.domain;

public enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    /** Maps a 0-100 risk score to a severity band. */
    public static Severity fromScore(int score) {
        if (score >= 90) return CRITICAL;
        if (score >= 70) return HIGH;
        if (score >= 45) return MEDIUM;
        return LOW;
    }
}
