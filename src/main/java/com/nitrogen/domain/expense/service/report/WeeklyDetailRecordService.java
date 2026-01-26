package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.dto.report.detail.EvaluationSummary;
import com.nitrogen.domain.expense.dto.report.detail.ExpenseSimpleResponse;
import com.nitrogen.domain.expense.dto.report.detail.WeeklyDetailReportResponse;
import com.nitrogen.domain.expense.dto.report.summary.EmotionSummary;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationFeedback;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class WeeklyDetailRecordService {
    private final ExpenseRepository expenseRepository;

    public WeeklyDetailReportResponse generateWeeklyDetailReport(Long userId, LocalDate start, LocalDate end, String weekRange) {

        // {주차별 총 소비 금액}
        List<Expense> allExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetween(userId, start, end);

        // 주간 평균 만족도 점수를 계산해 하단 회색 박스의 랜덤 문구 생성
        double avgScore = expenseRepository.calculateAverageEvaluationScore(userId, start, end);
        String evaluationMessage = EvaluationFeedback.getRandomSentence(avgScore);

        // 각 만족도별 소비 건수와 총액 - 중앙 리스트 UI
        List<EvaluationSummary> evaluationSummaries = Arrays.stream(EvaluationType.values())
                .map(type -> new EvaluationSummary(
                        type,
                        allExpenses.stream().filter(e -> e.getEvaluationType() == type).count(),
                        allExpenses.stream().filter(e -> e.getEvaluationType() == type).mapToLong(Expense::getAmount).sum()
                )).toList();

        // 이번 주 가장 빈번했던 {마음할목} 선정
        EmotionType topEmotion = allExpenses.stream()
                .collect(Collectors.groupingBy(Expense::getEmotionType, Collectors.counting()))
                .entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(EmotionType.TYPE_B);

        // 선정된 {마음항목} 내에서 가장 비싼 지출 3건 조회
        List<Expense> top3Expenses = expenseRepository.findTop3ByEmotion(userId, start, end, topEmotion.name());

        // 가장 많이 소비한 마음의 총액과 주간 전체 소비 총액 계산
        long topEmotionTotalAmount = allExpenses.stream()
                .filter(e -> e.getEmotionType() == topEmotion)
                .mapToLong(Expense::getAmount).sum();

        long weeklyTotalAmount = allExpenses.stream().mapToLong(Expense::getAmount).sum();

        List<ExpenseSimpleResponse> top3Response = top3Expenses.stream()
                .map(e -> new ExpenseSimpleResponse(e.getUsageHistory(), e.getAmount()))
                .toList();

        return new WeeklyDetailReportResponse(
                weekRange,
                new EmotionSummary(topEmotion.getEmotion_description(), topEmotionTotalAmount, (long) top3Expenses.size()),
                evaluationMessage,
                evaluationSummaries,
                top3Response,
                topEmotionTotalAmount,
                (long) allExpenses.size(),
                weeklyTotalAmount
        );
    }

}
