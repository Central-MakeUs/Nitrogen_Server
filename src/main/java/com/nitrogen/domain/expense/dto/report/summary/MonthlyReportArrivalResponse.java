package com.nitrogen.domain.expense.dto.report.summary;

public record MonthlyReportArrivalResponse(
        int year,
        int month,
        long totalAmount,
        boolean isChecked
) {}