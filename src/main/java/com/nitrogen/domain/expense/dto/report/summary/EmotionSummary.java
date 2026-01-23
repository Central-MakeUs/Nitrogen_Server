package com.nitrogen.domain.expense.dto.report.summary;

import com.nitrogen.domain.expense.entity.enums.EmotionType;

public record EmotionSummary(
        EmotionType emotionType,
        long count,
        long totalAmount
) {}
