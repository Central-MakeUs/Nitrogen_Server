package com.nitrogen.domain.expense.dto.report.summary;

import com.nitrogen.domain.expense.entity.enums.EmotionType;

public record EmotionSummary(
        String emotionDescription,
        long totalAmount,
        long count,
        String feedbackMessage
) {}
