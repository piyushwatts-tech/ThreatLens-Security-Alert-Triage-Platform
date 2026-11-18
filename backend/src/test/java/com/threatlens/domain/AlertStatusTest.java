package com.threatlens.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AlertStatusTest {
    @Test
    void workflowTransitions() {
        assertThat(AlertStatus.NEW.canTransitionTo(AlertStatus.INVESTIGATING)).isTrue();
        assertThat(AlertStatus.INVESTIGATING.canTransitionTo(AlertStatus.CLOSED)).isTrue();
        assertThat(AlertStatus.CLOSED.canTransitionTo(AlertStatus.INVESTIGATING)).isTrue(); // reopen
        assertThat(AlertStatus.CLOSED.canTransitionTo(AlertStatus.NEW)).isFalse();
    }
}
