package com.nitrogen.domain.expense.dto.report.detail;

public record ExpenseSimpleResponse(
        String usageHistory,
        long amount
) {}
