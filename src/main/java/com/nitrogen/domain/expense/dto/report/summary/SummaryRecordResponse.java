package com.nitrogen.domain.expense.dto.report.summary;

public record SummaryRecordResponse(
        MonthlyReportSummaryResponse monthlyReport,
        WeeklyReportResponse weeklyReport
) {}
