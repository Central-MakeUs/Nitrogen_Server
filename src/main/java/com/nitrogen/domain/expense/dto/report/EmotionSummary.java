package com.nitrogen.domain.expense.dto.report;

import com.nitrogen.domain.expense.entity.enums.EmotionType;

public record EmotionSummary(
        EmotionType emotionType,
        long totalAmount,
        long count
) {}
