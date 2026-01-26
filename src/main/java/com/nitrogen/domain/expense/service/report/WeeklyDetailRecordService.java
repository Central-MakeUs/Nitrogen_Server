package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class WeeklyDetailRecordService {
    private final ExpenseRepository expenseRepository;

    public WeeklyDetailRecordService generateWeeklyDetailReport(Long userId, String weekRange) {

        List<Expense> weeklyDetailExpenses = expenseRepository.findExpenses(
                userId,
                start,
                end,
                evaluationType
        )
        // 구현 예정
        return this;
    }

}
