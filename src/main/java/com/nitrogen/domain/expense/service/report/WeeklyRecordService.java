package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.dto.calendar.MonthlyAmountDTO;
import com.nitrogen.domain.expense.dto.report.summary.EmotionSummary;
import com.nitrogen.domain.expense.dto.report.summary.MonthlyReportArrivalResponse;
import com.nitrogen.domain.expense.dto.report.summary.WeeklyReportResponse;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.MonthlyReportRead;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.repository.MonthlyReportReadRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.WeekFields;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class WeeklyRecordService {

    private final ExpenseRepository expenseRepository;
    private final MonthlyReportReadRepository monthlyReportReadRepository;
    private final UserRepository userRepository;

    // 월간 분석리포트 도착 목록 조회 api
    @Transactional(readOnly = true)
    public List<MonthlyReportArrivalResponse> getMonthlyReportArrivals(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        LocalDate now = LocalDate.now();
        List<MonthlyAmountDTO> monthsWithExpenses = expenseRepository.findMonthlyTotalsByUserId(userId);

        // 유저가 확인한 월 목록
        Set<LocalDate> checkedMonths = monthlyReportReadRepository.findAllByUser(user).stream()
                .map(MonthlyReportRead::getReportMonth)
                .collect(Collectors.toSet());

        return monthsWithExpenses.stream()
                .map(dto -> {
                    LocalDate startOfMonth = LocalDate.parse(dto.getMonth());
                    LocalDate reportOpenDate = startOfMonth.plusMonths(1);

                    // 다음달 1일이 지나야 리포트가 "도착"한 상태
                    boolean isArrived = !now.isBefore(reportOpenDate);
                    if (!isArrived) return null;

                    boolean isChecked = checkedMonths.contains(startOfMonth);

                    return new MonthlyReportArrivalResponse(
                            startOfMonth.getYear(),
                            startOfMonth.getMonthValue(),
                            isChecked
                    );
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    // 월간 분석리포트 확인 처리 api
    @Transactional
    public void checkMonthlyReport(Long userId, int year, int month) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        LocalDate reportMonth = LocalDate.of(year, month, 1);

        if (monthlyReportReadRepository.existsByUserAndReportMonth(user, reportMonth)) {
            return; // 이미 확인한 리포트
        }

        monthlyReportReadRepository.save(new MonthlyReportRead(user, reportMonth));
    }

    public WeeklyReportResponse generateWeeklyReport(Long userId, LocalDate start, LocalDate end, int week) {

        List<Expense> weeklyExpenses = expenseRepository.findAllByUserIdAndExpendedAtBetweenWithCategory(userId, start, end);

        long weeklyTotalAmount = weeklyExpenses.stream().mapToLong(Expense::getAmount).sum();

        DateTimeFormatter startFormatter = DateTimeFormatter.ofPattern("yy.MM.dd");
        DateTimeFormatter endFormatter = DateTimeFormatter.ofPattern("MM.dd");
        String weekPeriod = String.format("%s ~ %s", start.format(startFormatter), end.format(endFormatter));

        LocalDate thursday = start.plusDays(3);
        int isoYear = thursday.get(WeekFields.ISO.weekBasedYear());
        int isoMonth = thursday.getMonthValue();

        Map<EmotionType, List<Expense>> grouped = weeklyExpenses.stream()
                .collect(Collectors.groupingBy(Expense::getEmotionType));

        List<EmotionSummary> emotionDetails = grouped.entrySet().stream()
                .map(entry -> new EmotionSummary(
                        entry.getKey().getEmotion_description(),
                        entry.getValue().stream().mapToLong(Expense::getAmount).sum(),
                        entry.getValue().size(),
                        null
                ))
                .sorted(getEmotionComparator())
                .toList();

        EmotionSummary topEmotion = emotionDetails.isEmpty() ? null : emotionDetails.get(0);

        String weekRange = String.format("%d년 %d월 %d주차", isoYear, isoMonth, week);
        return new WeeklyReportResponse(weekRange, weekPeriod, weeklyTotalAmount, topEmotion, emotionDetails);
    }
    /**
     * 지출 금액 내림차순 -> 소비 건수 내림차순 -> 이름(ㄱㄴㄷ) 오름차순
     */
    private Comparator<EmotionSummary> getEmotionComparator() {
        return Comparator.comparingLong(EmotionSummary::totalAmount).reversed()
                .thenComparing(Comparator.comparingLong(EmotionSummary::count).reversed())
                .thenComparing(EmotionSummary::emotionDescription);
    }
}
