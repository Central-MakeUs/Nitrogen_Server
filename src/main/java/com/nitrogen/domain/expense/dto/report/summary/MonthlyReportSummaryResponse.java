package com.nitrogen.domain.expense.dto.report.summary;

public record MonthlyReportSummaryResponse(
        String month,
        long totalAmount,
        boolean isOpened
) {}
