package com.nitrogen.domain.alert.repository;

import com.nitrogen.domain.alert.entity.Alert;
import com.nitrogen.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    // 특정 유저의 알림을 생성일자 기준 내림차순(최신순)으로 조회
    List<Alert> findAllByUserOrderByCreatedAtDesc(User user);
}
