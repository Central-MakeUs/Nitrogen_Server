package com.nitrogen.domain.expense.service.report.remind_grouping_expenselist;

import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.EvaluationGroupResponse;
import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.ExpenseItemResponse;
import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.WeeklyExpenseDetailResponse;
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
public class WeeklyExpenseDetailService {

    private final ExpenseRepository expenseRepository;

    // 선택한 마음항목에 해당하는 지출만 필터링한뒤 그 안에서 회고별로 소비 상세 내역 조회
    public WeeklyExpenseDetailResponse getWeeklyExpenseDetailList(Long userId, LocalDate start, LocalDate end, String weekRange, EmotionType emotionType) {

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

        return new WeeklyExpenseDetailResponse(
                weekRange,
                emotionTitle,
                totalCount,
                totalAmount,
                evaluationGroups
        );
    }
}
