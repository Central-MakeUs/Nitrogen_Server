package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Expense;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {
}
