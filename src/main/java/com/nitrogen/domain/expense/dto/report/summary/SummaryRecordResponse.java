package com.nitrogen.domain.expense.dto.report.summary;

import java.util.List;

public record SummaryRecordResponse(
        MonthlyReportSummaryResponse monthlyReport,
        List<WeeklyReportResponse> weeklyReports
) {}
