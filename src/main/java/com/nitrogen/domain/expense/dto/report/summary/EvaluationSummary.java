package com.nitrogen.domain.expense.dto.report.summary;

import com.nitrogen.domain.expense.entity.enums.EvaluationType;

public record EvaluationSummary (
    EvaluationType evaluationType,
    long count,
    long totalAmount
){}
