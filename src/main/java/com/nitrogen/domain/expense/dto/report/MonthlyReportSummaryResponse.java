package com.nitrogen.domain.expense.dto.report;

public record MonthlyReportSummaryResponse(
        String month,            // 2025년 1월
        long totalAmount,        // 월 총금액
        boolean isOpened         // 오픈가능여부
) {}
