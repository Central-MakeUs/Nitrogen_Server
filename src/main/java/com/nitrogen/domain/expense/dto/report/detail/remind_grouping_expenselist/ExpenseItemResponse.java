package com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist;

public record ExpenseItemResponse(
        String usageHistory,  // 서광서점
        String categoryName,  // 교육
        long amount           // 43,000원
) {}