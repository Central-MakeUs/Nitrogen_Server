package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.report.MonthlyReportSummaryResponse;
import com.nitrogen.domain.expense.dto.report.SummaryRecordResponse;
import com.nitrogen.domain.expense.dto.report.WeeklyReportResponse;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.service.report.WeeklyRecordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.temporal.TemporalAdjusters;
import java.time.temporal.WeekFields;

@RestController
@RequestMapping("/api/expense")
@RequiredArgsConstructor
@Tag(name = "Expense Report", description = "소비 분석 리포트 관련 API")
public class ExpenseReportController {

    private final WeeklyRecordService weeklyRecordService;
    private final ExpenseRepository expenseRepository;

    @Operation(summary = "메인화면 분석 리포트 조회", description = "이번 달 총 소비 금액과 지난주 주간 분석 리포트를 한 번에 조회합니다.")
    @GetMapping("/summary_record")
    public ResponseEntity<SummaryRecordResponse> getSummaryRecord(@RequestParam("userId") Long userId) {
        LocalDate now = LocalDate.now();

        // 월별 리포트 데이터 준비 https://m.blog.naver.com/seek316/222319652865
        LocalDate startOfMonth = now.withDayOfMonth(1);
        LocalDate endOfMonth = now.withDayOfMonth(now.lengthOfMonth());
        long monthlyTotalAmount = expenseRepository.calculateMonthlyTotal(userId, startOfMonth, endOfMonth);

        // 월별 리포트는 다음달 1일에 오픈
        boolean isOpened = false;
        String monthTitle = String.format("%d년 %d월 소비 현황", now.getYear(), now.getMonthValue());
        MonthlyReportSummaryResponse monthlyReport = new MonthlyReportSummaryResponse(monthTitle, monthlyTotalAmount, isOpened);

        // 주간 리포트 데이터 준비 (직전 주차 계산)
        LocalDate lastMonday = now.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).minusWeeks(1);
        LocalDate lastSunday = lastMonday.plusDays(6);

        // 현재 몇 주차인지 계산
        int weekOfMonth = lastMonday.get(WeekFields.ISO.weekOfMonth());

        WeeklyReportResponse weeklyReport = weeklyRecordService.generateWeeklyReport(
                userId,
                lastMonday,
                lastSunday,
                weekOfMonth
        );

        return ResponseEntity.ok(new SummaryRecordResponse(monthlyReport, weeklyReport));
    }
}
