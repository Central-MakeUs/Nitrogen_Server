package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class WeeklyDetailRecordService {
    private final ExpenseRepository expenseRepository;

    public WeeklyDetailRecordService generateWeeklyDetailReport(Long userId, String weekRange) {

        // 구현 예정
        return this;
    }

}
