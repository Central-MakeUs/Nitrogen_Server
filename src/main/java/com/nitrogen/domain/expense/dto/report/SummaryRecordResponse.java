package com.nitrogen.domain.expense.dto.report;

public record SummaryRecordResponse(
        MonthlyReportSummaryResponse monthlyReport,
        WeeklyReportResponse weeklyReport
) {}
