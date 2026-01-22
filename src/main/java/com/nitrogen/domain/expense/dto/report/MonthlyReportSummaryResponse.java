package com.nitrogen.domain.expense.dto.report;

public record MonthlyReportSummaryResponse(
        String month,
        long totalAmount,
        boolean isOpened
) {}
