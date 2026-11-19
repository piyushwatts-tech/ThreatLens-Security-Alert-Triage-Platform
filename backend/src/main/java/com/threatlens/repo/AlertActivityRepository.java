package com.threatlens.repo;

import com.threatlens.domain.AlertActivity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertActivityRepository extends JpaRepository<AlertActivity, Long> {
    List<AlertActivity> findByAlertIdOrderByCreatedAtAsc(Long alertId);
}
