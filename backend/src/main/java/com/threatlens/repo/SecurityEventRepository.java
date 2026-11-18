package com.threatlens.repo;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findByEventTypeInAndEventTimeBetweenOrderByEventTimeAsc(
            Collection<EventType> types, Instant from, Instant to);

    @Query("select min(e.eventTime), max(e.eventTime) from SecurityEvent e where e.batchId = :batchId")
    List<Object[]> timeRangeOfBatch(String batchId);

    @Query("select min(e.eventTime), max(e.eventTime) from SecurityEvent e")
    List<Object[]> timeRange();

    @Query("select e.source, e.eventType, count(e) from SecurityEvent e group by e.source, e.eventType")
    List<Object[]> countBySourceAndType();
}
