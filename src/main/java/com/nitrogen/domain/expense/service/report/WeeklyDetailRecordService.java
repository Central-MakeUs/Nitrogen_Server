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
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class WeeklyDetailRecordService {
    private final ExpenseRepository expenseRepository;

    public WeeklyDetailReportResponse generateWeeklyDetailReport(Long userId, LocalDate start, LocalDate end, String weekRange) {

        // {주차별 총 소비 금액}
        List<Expense> allExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetweenWithCategory(userId, start, end);

        // 이번 주 가장 빈번했던 {마음항목} 선정
        EmotionType topEmotion = allExpenses.stream()
                .collect(Collectors.groupingBy(Expense::getEmotionType, Collectors.counting()))
                .entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(EmotionType.TYPE_B);

        // 상단: 가장 많은 마음항목의 소비회고 완료 건에 대한 만족도 평균점수
        double topEmotionAvgScore = allExpenses.stream()
                .filter(e -> e.getEmotionType() == topEmotion)
                .filter(e -> e.getEvaluationType() != null)
                .mapToDouble(e -> e.getEvaluationType().getScore())
                .average()
                .orElse(0.0);

        // 하단: 전체 주간 만족도 평균점수
        double avgScore = expenseRepository.calculateAverageSatisfactionScore(userId, start, end);

        long seed = Objects.hash(userId, start);
        String emotionFeedbackMessage = EvaluationFeedback.getRandomSentence(topEmotionAvgScore, seed); // 상단 (가장 많은 마음항목 기준)
        String evaluationFeedbackMessage = EvaluationFeedback.getRandomSentence(avgScore, seed); // 하단 (전체 주간 기준)

        // 각 만족도별 소비 건수와 총액 - 중앙 리스트 UI
        List<EvaluationSummary> evaluationSummaries = Arrays.stream(EvaluationType.values())
                .map(type -> new EvaluationSummary(
                        type,
                        allExpenses.stream().filter(e -> e.getEvaluationType() == type).count(),
                        allExpenses.stream().filter(e -> e.getEvaluationType() == type).mapToLong(Expense::getAmount).sum()
                )).toList();

        // 선정된 {마음항목} 내에서 가장 비싼 지출 3건 조회
        List<Expense> top3Expenses = expenseRepository.findTop3ByEmotion(userId, start, end, topEmotion.name());

        /*
        금액 내림차순 > 건수 내림차순 > 이름 오름차순
        */
        Map<EmotionType, List<Expense>> emotionGrouped = allExpenses.stream()
                .collect(Collectors.groupingBy(Expense::getEmotionType));

        List<EmotionSummary> emotionDetails = emotionGrouped.entrySet().stream()
                .map(entry -> {
                    double emotionAvgScore = entry.getValue().stream()
                            .filter(e -> e.getEvaluationType() != null)
                            .mapToDouble(e -> e.getEvaluationType().getScore())
                            .average()
                            .orElse(0.0);
                    return new EmotionSummary(
                            entry.getKey().getEmotion_description(),
                            entry.getValue().stream().mapToLong(Expense::getAmount).sum(),
                            entry.getValue().size(),
                            EvaluationFeedback.getRandomSentence(emotionAvgScore, seed)
                    );
                })
                .sorted(Comparator.comparingLong(EmotionSummary::totalAmount).reversed()
                                .thenComparing(Comparator.comparingLong(EmotionSummary::count).reversed())
                        .thenComparing(EmotionSummary::emotionDescription))
                .toList();

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
                emotionFeedbackMessage,
                new EmotionSummary(topEmotion.getEmotion_description(), topEmotionTotalAmount, (long) top3Expenses.size(), emotionFeedbackMessage),
                evaluationFeedbackMessage,
                evaluationSummaries,
                emotionDetails,
                top3Response,
                topEmotionTotalAmount,
                (long) allExpenses.size(),
                weeklyTotalAmount
        );
    }

}
