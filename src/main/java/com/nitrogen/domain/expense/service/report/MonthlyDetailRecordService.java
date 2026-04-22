package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.dto.report.summary.EmotionSummary;
import com.nitrogen.domain.expense.dto.report.summary.EvaluationSummary;
import com.nitrogen.domain.expense.dto.report.detail.ExpenseSimpleResponse;
import com.nitrogen.domain.expense.dto.report.detail.MonthlyDetailReportResponse;
import com.nitrogen.domain.expense.dto.report.summary.EmotionDetailSummary;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationFeedback;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MonthlyDetailRecordService {
    private final ExpenseRepository expenseRepository;

    public MonthlyDetailReportResponse generateMonthlyDetailReport(Long userId, LocalDate start, LocalDate end, String monthTitle) {

        // {월간 총 소비 금액}
        List<Expense> allExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetweenWithCategory(userId, start, end);

        // 이번 달 가장 빈번했던 {마음항목} 선정
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

        // 하단: 전체 월간 만족도 평균점수
        double avgScore = expenseRepository.calculateAverageSatisfactionScore(userId, start, end);

        long seed = Objects.hash(userId, start);
        String emotionFeedbackMessage = EvaluationFeedback.getRandomSentence(topEmotionAvgScore, seed); // 상단 (가장 많은 마음항목 기준)
        String evaluationFeedbackMessage = EvaluationFeedback.getRandomSentence(avgScore, seed); // 하단 (전체 월간 기준)

        // 각 만족도별 소비 건수와 총액 - 중앙 리스트 UI
        Map<EvaluationType, List<Expense>> evalGrouped = allExpenses.stream()
                .filter(e -> e.getEvaluationType() != null)
                .collect(Collectors.groupingBy(Expense::getEvaluationType));

        List<EvaluationSummary> evaluationSummaries = Arrays.stream(EvaluationType.values())
                .map(type ->{
                    List<Expense> group = evalGrouped.getOrDefault(type, List.of());
                    return new EvaluationSummary(type, group.size(), group.stream().mapToLong(Expense::getAmount).sum());
                }).toList();

        // 선정된 {마음항목} 내에서 가장 비싼 지출 3건 조회
        List<Expense> top3Expenses = expenseRepository.findTop3ByEmotion(userId, start, end, topEmotion.name());

        /*
        금액 내림차순 > 건수 내림차순 > 이름 오름차순
        */
        Map<EmotionType, List<Expense>> emotionGrouped = allExpenses.stream()
                .collect(Collectors.groupingBy(Expense::getEmotionType));

        List<EmotionDetailSummary> emotionDetails = emotionGrouped.entrySet().stream()
                .map(entry -> {
                    List<Expense> emotionExpenses = entry.getValue();
                    double emotionAvgScore = emotionExpenses.stream()
                            .filter(e -> e.getEvaluationType() != null)
                            .mapToDouble(e -> e.getEvaluationType().getScore())
                            .average()
                            .orElse(0.0);

                    Map<EvaluationType, List<Expense>> perEmotionEvalGrouped = emotionExpenses.stream()
                            .filter(e -> e.getEvaluationType() != null)
                            .collect(Collectors.groupingBy(Expense::getEvaluationType));

                    List<EvaluationSummary> perEmotionEvalSummaries = Arrays.stream(EvaluationType.values())
                            .map(type -> {
                                List<Expense> group = perEmotionEvalGrouped.getOrDefault(type, List.of());
                                return new EvaluationSummary(type, group.size(), group.stream().mapToLong(Expense::getAmount).sum());
                            }).toList();

                    return new EmotionDetailSummary(
                            entry.getKey().getEmotion_description(),
                            emotionExpenses.stream().mapToLong(Expense::getAmount).sum(),
                            emotionExpenses.size(),
                            EvaluationFeedback.getRandomSentence(emotionAvgScore, seed),
                            perEmotionEvalSummaries
                    );
                })
                .sorted(Comparator.comparingLong(EmotionDetailSummary::totalAmount).reversed()
                                .thenComparing(Comparator.comparingLong(EmotionDetailSummary::count).reversed())
                        .thenComparing(EmotionDetailSummary::emotionDescription))
                .toList();

        // 가장 많이 소비한 {마음항목}의 총액과 월간 전체 소비 총액 계산
        List<Expense> topEmotionExpenses = emotionGrouped.getOrDefault(topEmotion, List.of());
        long topEmotionTotalAmount = topEmotionExpenses.stream().mapToLong(Expense::getAmount).sum();
        long topEmotionCount = topEmotionExpenses.size();

        long monthlyTotalAmount = allExpenses.stream().mapToLong(Expense::getAmount).sum();

        List<ExpenseSimpleResponse> top3Response = top3Expenses.stream()
                .map(e -> new ExpenseSimpleResponse(e.getUsageHistory(), e.getAmount()))
                .toList();

        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy.MM.dd");

        return new MonthlyDetailReportResponse(
                monthTitle,
                start.format(fmt),
                end.format(fmt),
                emotionFeedbackMessage,
                new EmotionSummary(topEmotion.getEmotion_description(), topEmotionTotalAmount, topEmotionCount, emotionFeedbackMessage),
                evaluationFeedbackMessage,
                evaluationSummaries,
                emotionDetails,
                top3Response,
                topEmotionTotalAmount,
                (long) allExpenses.size(),
                monthlyTotalAmount
        );
    }

}
