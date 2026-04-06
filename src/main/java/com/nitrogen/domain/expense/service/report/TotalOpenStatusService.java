package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.dto.weeklyAndmonthly.TotalOpenStatusResponse;
import com.nitrogen.domain.expense.dto.weeklyAndmonthly.WeeklyOpenStatus;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.List;
import java.time.DayOfWeek;

@Service
@RequiredArgsConstructor
public class TotalOpenStatusService {

    private final ExpenseRepository expenseRepository;

    @Transactional(readOnly = true)
    public TotalOpenStatusResponse getTotalOpenStatus(Long userId, int year, int month) {
        LocalDate startOfMonth = LocalDate.of(year, month, 1);
        LocalDate endOfMonth = startOfMonth.withDayOfMonth(startOfMonth.lengthOfMonth());
        LocalDate now = LocalDate.now();

        // 월간 총액
        long totalAmount = expenseRepository.calculateMonthlyTotal(userId, startOfMonth, endOfMonth);

        // 월간 리포트 오픈 여부 (다음달 1일 이후)
        boolean monthlyIsOpened = !now.isBefore(startOfMonth.plusMonths(1));

        // 주차별 오픈 상태
        List<WeeklyOpenStatus> weeklyReports = new ArrayList<>();
        LocalDate monday = startOfMonth.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));

        int weekNumber = 1;
        while (!monday.isAfter(endOfMonth)) {
            LocalDate sunday = monday.plusDays(6);

            boolean hasExpense = expenseRepository.existsByUserUserIdAndExpendedAtBetween(userId, monday, sunday);
            if (hasExpense) {
                boolean isOpened = now.isAfter(sunday);
                weeklyReports.add(new WeeklyOpenStatus(weekNumber, isOpened));
            }

            monday = monday.plusWeeks(1);
            weekNumber++;
        }

        return new TotalOpenStatusResponse(year, month, totalAmount, weeklyReports, monthlyIsOpened);
    }
}