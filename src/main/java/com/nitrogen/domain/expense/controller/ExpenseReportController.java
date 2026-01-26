package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.report.detail.WeeklyDetailReportResponse;
import com.nitrogen.domain.expense.dto.report.summary.MonthlyReportSummaryResponse;
import com.nitrogen.domain.expense.dto.report.summary.SummaryRecordResponse;
import com.nitrogen.domain.expense.dto.report.summary.WeeklyReportResponse;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.service.report.WeeklyRecordService;
import com.nitrogen.domain.expense.service.report.WeeklyDetailRecordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
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
    private final WeeklyDetailRecordService weeklyDetailRecordService;
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

    @Operation(summary = "주간 분석 상세 리포트 조회", description = "특정 주차의 감정 분석, 만족도 통계, TOP 3 지출 내역 등 상세 데이터를 조회합니다.")
    @GetMapping("/weekly_detail")
    public ResponseEntity<WeeklyDetailReportResponse> getWeeklyDetailReport(
            @RequestParam("userId") Long userId,
            @RequestParam("date") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {

        LocalDate start = date.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        LocalDate end = start.plusDays(6);

        int month = date.getMonthValue();
        int weekOfMonth = date.get(WeekFields.ISO.weekOfMonth());
        String weekRange = String.format("%d년 %d월 %d주차 분석 리포트", date.getYear(), month, weekOfMonth);

        WeeklyDetailReportResponse response = weeklyDetailRecordService.generateWeeklyDetailReport(
                userId, start, end, weekRange);

        return ResponseEntity.ok(response);
    }
}
