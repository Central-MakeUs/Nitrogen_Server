package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Expense;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;

import java.util.List;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {
    // 특정 날짜 지출내역 조회
    List<Expense> findAllByUserUserIdAndExpendedAt(Long userId, LocalDate expendedAt);

    // 월별 총액을 위한 계산
    @Query("SELECT COALESCE(SUM(e.amount), 0) FROM Expense e WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    long calculateMonthlyTotal(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end);
    // 특정 기간 내 사용자의 지출 내역 조회
    @Query("SELECT e FROM Expense e WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    List<Expense> findAllByUserIdAndExpendedAtBetween(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end);

    
}
