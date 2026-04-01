package com.nitrogen.domain.expense.dto.report.summary;

public record MonthlyReportArrivalResponse(
        int year,
        int month,
        boolean isChecked
) {}