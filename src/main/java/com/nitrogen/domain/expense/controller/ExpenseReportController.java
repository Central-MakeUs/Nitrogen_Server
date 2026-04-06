package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.report.detail.WeeklyDetailReportResponse;
import com.nitrogen.domain.expense.dto.report.summary.MonthlyReportArrivalResponse;
import com.nitrogen.domain.expense.dto.report.summary.MonthlyReportSummaryResponse;
import com.nitrogen.domain.expense.dto.report.summary.SummaryRecordResponse;
import com.nitrogen.domain.expense.dto.report.summary.WeeklyReportResponse;
import com.nitrogen.domain.expense.dto.weeklyAndmonthly.TotalOpenStatusResponse;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.service.inquiry.ExpenseInquiryService;
import com.nitrogen.domain.expense.service.report.DailyRetrospectReportService;
import com.nitrogen.domain.expense.service.report.WeeklyRecordService;
import com.nitrogen.domain.expense.service.report.TotalOpenStatusService;
import com.nitrogen.domain.expense.service.report.WeeklyDetailRecordService;
import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.TemporalAdjusters;
import java.time.temporal.WeekFields;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/expense")
@RequiredArgsConstructor
@Tag(name = "Expense Report", description = "소비 분석 리포트 관련 API")
public class ExpenseReportController {

    private final WeeklyRecordService weeklyRecordService;
    private final WeeklyDetailRecordService weeklyDetailRecordService;
    private final DailyRetrospectReportService dailyRetrospectReportService;
    private final ExpenseRepository expenseRepository;
    private final ExpenseInquiryService expenseInquiryService;
    private final TotalOpenStatusService totalOpenStatusService;

    @Operation(summary = "메인화면 분석 리포트 조회", description = "이번 달 총 소비 금액과 지난주 주간 분석 리포트를 한 번에 조회합니다.")
    @GetMapping("/summary_record")
    public ApiResponse<SummaryRecordResponse> getSummaryRecord(@AuthenticationPrincipal CustomUserDetails userDetails) {
        Long userId = userDetails.getUserId();
        LocalDateTime nowDateTime = LocalDateTime.now();
        LocalDate nowDate = nowDateTime.toLocalDate();

        // 월별 리포트 데이터 준비 https://m.blog.naver.com/seek316/222319652865
        LocalDate startOfMonth = nowDate.withDayOfMonth(1);
        LocalDate endOfMonth = nowDate.withDayOfMonth(nowDate.lengthOfMonth());
        long monthlyTotalAmount = expenseRepository.calculateMonthlyTotal(userId, startOfMonth, endOfMonth);

        // 월별 리포트는 다음달 1일에 오픈
        boolean isOpened = false;
        String yearTitle = String.valueOf(nowDate.getYear());
        String monthTitle = String.format("%d년 %d월 소비 현황", nowDate.getYear(), nowDate.getMonthValue());
        MonthlyReportSummaryResponse monthlyReport = new MonthlyReportSummaryResponse(yearTitle, monthTitle, monthlyTotalAmount, isOpened);

        List<WeeklyReportResponse> weeklyReports = new ArrayList<>();

        // 월요일 오전 8시 생성 기준점 계산
        LocalDateTime thisWeekGenTime = nowDate.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).atTime(8, 0);

        LocalDate lastAvailableMonday = nowDateTime.isBefore(thisWeekGenTime)
                ? nowDate.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).minusWeeks(2)
                : nowDate.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).minusWeeks(1);

        LocalDate checkDate = startOfMonth.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));

        while (!checkDate.isAfter(lastAvailableMonday)) {
            LocalDate sunday = checkDate.plusDays(6);

            if (expenseRepository.existsByUserUserIdAndExpendedAtBetween(userId, checkDate, sunday)) {
                int weekOfMonth = checkDate.get(WeekFields.ISO.weekOfMonth());
                weeklyReports.add(weeklyRecordService.generateWeeklyReport(userId, checkDate, sunday, weekOfMonth));
            }
            checkDate = checkDate.plusWeeks(1);
        }

        return ApiResponse.onSuccess(new SummaryRecordResponse(monthlyReport, weeklyReports));
    }

    @Operation(summary = "주간 분석 상세 리포트 조회", description = "특정 주차의 감정 분석, 만족도 통계, TOP 3 지출 내역 등 상세 데이터를 조회합니다.")
    @GetMapping("/weekly_detail")
    public ApiResponse<WeeklyDetailReportResponse> getWeeklyDetailReport(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("date") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {

        Long userId = userDetails.getUserId();

        LocalDate start = date.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        LocalDate end = start.plusDays(6);

        int month = date.getMonthValue();
        int weekOfMonth = date.get(WeekFields.ISO.weekOfMonth()) + 1;
        String weekRange = String.format("%d년 %d월 %d주차 분석 리포트", date.getYear(), month, weekOfMonth);

        WeeklyDetailReportResponse response = weeklyDetailRecordService.generateWeeklyDetailReport(
                userId, start, end, weekRange);

        return ApiResponse.onSuccess(response);
    }

    @Operation(summary = "일별 종합 소비 만족도 조회", description = "당일 모든 지출에 대한 회고가 완료된 경우, 전체 만족도 평균을 문구로 반환합니다.")
    @GetMapping("/daily_satisfaction")
    public ApiResponse<String> getDailyAverageSatisfaction(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("date") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {

        Long userId = userDetails.getUserId();
        String satisfactionMessage = dailyRetrospectReportService.getDailyAverageSatisfaction(userId, date);

        return ApiResponse.onSuccess(satisfactionMessage);
    }

    @Operation(summary = "월별 지출 총액 조회", description = "소비 기록이 존재하는 모든 달의 지출 총액 목록을 최신순으로 조회합니다.")
    @GetMapping("/monthly_totals")
    public ApiResponse<List<MonthlyReportSummaryResponse>> getMonthlyTotalList(
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        Long userId = userDetails.getUserId();
        List<MonthlyReportSummaryResponse> response = expenseInquiryService.getMonthlyTotalList(userId);

        return ApiResponse.onSuccess(response);
    }

    @Operation(summary = "월 + 주차별 open 상태 통합 조회",
            description = "특정 월의 총 지출액, 주차별 리포트 오픈 여부, 월간 리포트 오픈 여부를 한 번에 조회합니다.")
    @GetMapping("/total_open_status")
    public ApiResponse<TotalOpenStatusResponse> getTotalOpenStatus(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam int year,
            @RequestParam int month) {

        Long userId = userDetails.getUserId();
        TotalOpenStatusResponse response = totalOpenStatusService.getTotalOpenStatus(userId, year, month);

        return ApiResponse.onSuccess(response);
    }

    @Operation(summary = "분석 리포트 도착 알림 카드 조회",
            description = "생성한 월별 분석 리포트 알림 카드 목록을 반환합니다. 확인한 리포트는 isChecked=true로\n" +
                    "  표시됩니다. 이전 달 미확인과 무관하게 최신 리포트도 노출됩니다.")
    @GetMapping("/report_arrivals")
    public ApiResponse<List<MonthlyReportArrivalResponse>> getReportArrivals(
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        Long userId = userDetails.getUserId();
        List<MonthlyReportArrivalResponse> response = weeklyRecordService.getMonthlyReportArrivals(userId);

        return ApiResponse.onSuccess(response);
    }

    @Operation(summary = "월별 분석 리포트 확인 처리",
            description = "유저가 특정 월의 분석 리포트를 확인했음을 기록합니다.")
    @PatchMapping("/report_arrivals/{year}/{month}/check")
    public ApiResponse<Map<String, Boolean>> checkReport(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable int year,
            @PathVariable int month) {

        Long userId = userDetails.getUserId();
        weeklyRecordService.checkMonthlyReport(userId, year, month);

        return ApiResponse.onSuccess(Map.of("isChecked", true));
    }
}
