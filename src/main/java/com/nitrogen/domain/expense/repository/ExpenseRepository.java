package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Expense;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDate;

import java.util.List;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {

    List<Expense> findAllByUserIdAndExpendedAt(Long userId, LocalDate expendedAt);
}
