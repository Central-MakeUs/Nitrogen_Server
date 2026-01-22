package com.nitrogen.domain.expense.dto.report;

import com.nitrogen.domain.expense.entity.enums.EmotionType;

import java.util.List;

public record WeeklyReportResponse(
        String weekRange,
        long weeklyTotalAmount,
        EmotionSummary topEmotion,
        List<EmotionSummary> emotionDetails
) {}
