package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Expense;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;

import java.util.List;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {

    // 월별 총액을 위한 계산
    @Query("SELECT COALESCE(SUM(e.amount), 0) FROM Expense e WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    long calculateMonthlyTotal(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end);
    List<Expense> findAllByUserIdAndExpendedAt(Long userId, LocalDate expendedAt);
}
