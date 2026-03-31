package com.nitrogen.domain.expense.dto.report.summary;

public record MonthlyReportSummaryResponse(
        String year,
        String month,
        long totalAmount,
        boolean isOpened // 월별 리포트 오픈 여부
) {}
