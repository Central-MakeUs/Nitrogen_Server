package com.nitrogen.domain.expense.dto.report.summary;

import com.fasterxml.jackson.annotation.JsonInclude;

public record EmotionSummary(
        String emotionDescription,
        long totalAmount,
        long count,
        @JsonInclude(JsonInclude.Include.NON_NULL)
        String feedbackMessage
) {}
