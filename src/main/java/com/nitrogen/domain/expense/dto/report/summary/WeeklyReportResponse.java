package com.nitrogen.domain.expense.dto.report.summary;

import java.util.List;

public record WeeklyReportResponse(
        String weekRange,
        long weeklyTotalAmount,
        EmotionSummary topEmotion,
        List<EmotionSummary> emotionDetails
) {}
