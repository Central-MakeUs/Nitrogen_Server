package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.SatisfactionLevel;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
public class DailyRetrospectReportService {

    private final ExpenseRepository expenseRepository;

    public String getDailyAverageSatisfaction(Long userId, LocalDate date) {

        List<Expense> dailyExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetween(userId, date, date);

        if (dailyExpenses.isEmpty()) {
            return "기록된 지출이 없습니다.";
        }
        boolean allRetrospectsCompleted = dailyExpenses.stream()
                .allMatch(expense -> expense.getEvaluationType() != null);

        if (!allRetrospectsCompleted) {
            return "소비 회고가 완료되지 않았습니다.";
        }
        double averageScore = expenseRepository.calculateAverageEvaluationScore(userId, date, date);

        return SatisfactionLevel.getDescriptionByAverage(averageScore);
    }
}
