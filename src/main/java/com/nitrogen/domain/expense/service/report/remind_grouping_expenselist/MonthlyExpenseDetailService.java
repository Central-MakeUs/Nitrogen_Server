package com.nitrogen.domain.expense.service.report.remind_grouping_expenselist;

import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.EvaluationGroupResponse;
import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.ExpenseItemResponse;
import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.MonthlyExpenseDetailResponse;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@RequiredArgsConstructor
public class MonthlyExpenseDetailService {

    private final ExpenseRepository expenseRepository;

    // 선택한 마음항목에 해당하는 지출만 필터링한뒤 그 안에서 회고별로 소비 상세 내역 조회
    public MonthlyExpenseDetailResponse getMonthlyExpenseDetailList(Long userId, int year, int month, EmotionType emotionType) {

        // year/month 기반으로 월 범위, monthTitle 자동 생성
        LocalDate start = LocalDate.of(year, month, 1);
        LocalDate end = start.withDayOfMonth(start.lengthOfMonth());
        String monthTitle = String.format("%d년 %d월", year, month);

        List<Expense> allExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetweenWithCategory(userId, start, end);

        List<Expense> filteredExpenses = allExpenses.stream()
                .filter(e -> e.getEmotionType() == emotionType)
                .toList();

        long totalAmount = filteredExpenses.stream().mapToLong(Expense::getAmount).sum();
        int totalCount = filteredExpenses.size();

        AtomicInteger stepCounter = new AtomicInteger(1);

        List<EvaluationGroupResponse> evaluationGroups = Arrays.stream(EvaluationType.values())
                .map(type -> {
                    List<ExpenseItemResponse> items = filteredExpenses.stream()
                            .filter(e -> e.getEvaluationType() == type)
                            .map(e -> new ExpenseItemResponse(
                                    e.getUsageHistory(),
                                    e.getCategory().getName(),
                                    e.getAmount()
                            ))
                            .toList();

                    if (items.isEmpty()) return null;

                    return new EvaluationGroupResponse(
                            stepCounter.getAndIncrement(),
                            type.getEvaluation_description(),
                            items.size(),
                            items.stream().mapToLong(ExpenseItemResponse::amount).sum(),
                            items
                    );
                })
                .filter(Objects::nonNull)
                .toList();

        String emotionTitle = String.format("%s 소비 상세 내역", emotionType.getEmotion_description());

        return new MonthlyExpenseDetailResponse(
                monthTitle,
                emotionTitle,
                totalCount,
                totalAmount,
                evaluationGroups
        );
    }
}
