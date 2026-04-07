package com.nitrogen.domain.expense.dto.report.summary;

import java.util.List;

public record EmotionDetailSummary(
        String emotionDescription,
        long totalAmount,
        long count,
        String feedbackMessage,
        List<EvaluationSummary> evaluationSummaries
) {}