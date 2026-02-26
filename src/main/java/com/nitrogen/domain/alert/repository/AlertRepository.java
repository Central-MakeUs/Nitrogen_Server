package com.nitrogen.domain.alert.repository;

import com.nitrogen.domain.alert.entity.Alert;
import com.nitrogen.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    // 읽지 않은 알림(false) 우선 + 그 안에서 최신순 정렬
    List<Alert> findAllByUserOrderByIsReadAscCreatedAtDesc(User user);

    // 전체 알림 최신순
    List<Alert> findAllByUserOrderByCreatedAtDesc(User user);

    // 읽지 않은 알림만 조회
    List<Alert> findAllByUserAndIsReadFalse(User user);

    // 읽지 않은 알림이 하나라도 존재하는지 여부 판단
    boolean existsByUserAndIsReadFalse(User user);
}
