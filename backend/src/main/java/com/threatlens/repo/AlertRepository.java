package com.threatlens.repo;

import com.threatlens.domain.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long>, JpaSpecificationExecutor<Alert> {

    boolean existsByFingerprint(String fingerprint);

    List<Alert> findByFingerprintIn(Collection<String> fingerprints);

    List<Alert> findByFirstSeenBetween(Instant from, Instant to);

    @Query("select a.severity, count(a) from Alert a group by a.severity")
    List<Object[]> countBySeverity();

    @Query("select a.status, count(a) from Alert a group by a.status")
    List<Object[]> countByStatus();

    @Query("select a.mitreTactic, count(a) from Alert a group by a.mitreTactic order by count(a) desc")
    List<Object[]> countByTactic();

    @Query("select a.ruleId, count(a) from Alert a group by a.ruleId order by count(a) desc")
    List<Object[]> countByRule();

    @Query(value = """
           select date_trunc(:bucket, first_seen) as bucket, severity, count(*)
           from alert group by 1, 2 order by 1
           """, nativeQuery = true)
    List<Object[]> timeline(String bucket);

    /** Mean minutes from alert creation to first close (MTTR proxy). */
    @Query(value = """
           select avg(extract(epoch from (c.closed_at - a.created_at)) / 60.0)
           from alert a join (select alert_id, min(created_at) closed_at from alert_activity
                              where to_status = 'CLOSED' group by alert_id) c on c.alert_id = a.id
           """, nativeQuery = true)
    Double meanMinutesToClose();
}
