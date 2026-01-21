package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Expense;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;

import java.util.List;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {

    // 월별 총액을 위한 계산
    @Query("SELECT COALESCE(SUM(e.amount), 0) FROM Expense e JOIN e.user u WHERE u.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    long calculateMonthlyTotal(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end);
    List<Expense> findAllByUserUserIdAndExpendedAt(Long userId, LocalDate expendedAt);
    // 특정 기간 내 사용자의 지출 내역 조회
    List<Expense> findAllByUserIdAndExpenseDateBetween(Long userId, LocalDate start, LocalDate end);

    // 월별 총 소비 금액 합산
    @Query("SELECT SUM(e.amount) FROM Expense e WHERE e.userId = :userId AND e.expenseDate BETWEEN :start AND :end")
    Long sumAmountByUserIdAndDateBetween(Long userId, LocalDate start, LocalDate end);
}
