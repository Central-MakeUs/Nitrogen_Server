package com.nitrogen.domain.expense.dto.report;

import com.nitrogen.domain.expense.entity.enums.EmotionType;

import java.util.List;

public record WeeklyReportResponse(
        String weekRange,
        long weeklyTotalAmount,        // 주차 총액
        EmotionSummary topEmotion,     // 가장 많이 지출한 감정정보
        List<EmotionSummary> emotionDetails // 금액 내림차순
) {}
