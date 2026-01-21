package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.dto.report.EmotionSummary;
import com.nitrogen.domain.expense.dto.report.WeeklyReportResponse;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.temporal.WeekFields;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class WeeklyRecordService {

    private final ExpenseRepository expenseRepository;

    public WeeklyReportResponse generateWeeklyReport(Long userId, LocalDate start, LocalDate end, int week) {

        System.out.println("조회 범위: " + start + " ~ " + end);
        System.out.println("로그인 유저 ID: " + userId);

        List<Expense> weeklyExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetween(userId, start, end);

        System.out.println("찾은 데이터 개수: " + weeklyExpenses.size());

        long weeklyTotalAmount = weeklyExpenses.stream().mapToLong(Expense::getAmount).sum();

        LocalDate thursday = start.plusDays(3);
        int isoYear = thursday.get(WeekFields.ISO.weekBasedYear());
        int isoMonth = thursday.getMonthValue();

        Map<EmotionType, List<Expense>> grouped = weeklyExpenses.stream()
                .collect(Collectors.groupingBy(Expense::getEmotionType));

        List<EmotionSummary> emotionDetails = grouped.entrySet().stream()
                .map(entry -> new EmotionSummary(
                        entry.getKey(),
                        entry.getValue().size(),
                        entry.getValue().stream().mapToLong(Expense::getAmount).sum()
                ))
                .sorted(getEmotionComparator())
                .toList();

        EmotionSummary topEmotion = emotionDetails.isEmpty() ? null : emotionDetails.get(0);

        String weekRange = String.format("%d년 %d월 %d주차", isoYear, isoMonth, week);
        return new WeeklyReportResponse(weekRange, weeklyTotalAmount, topEmotion, emotionDetails);
    }
    /**
     * 지출 금액 내림차순 -> 소비 건수 내림차순 -> 이름(ㄱㄴㄷ) 오름차순
     */
    private Comparator<EmotionSummary> getEmotionComparator() {
        return Comparator.comparingLong(EmotionSummary::totalAmount).reversed()
                .thenComparing(Comparator.comparingLong(EmotionSummary::count).reversed())
                .thenComparing(summary -> summary.emotionType().getEmotion_description());
    }
}
