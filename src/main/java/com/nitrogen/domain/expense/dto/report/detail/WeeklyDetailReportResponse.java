package com.nitrogen.domain.expense.dto.report.detail;

import com.nitrogen.domain.expense.dto.report.summary.EmotionSummary;

import java.util.List;

public record WeeklyDetailReportResponse(

        String weekRange, // 주간 범위
        String emotionFeedbackMessage, // 마음항목 관점 평균만족도 문장(상단)
        EmotionSummary topEmotion, // 가장 많이 소비한 마음
        String evaluationFeedbackMessage, // 소비회고 관점 평균만족도 문장(하단)
        List<EvaluationSummary> evaluationSummaries, // 가장 많이 소비한 마음
        List<EmotionSummary> emotionDetails, // 그아래로 전체 마음 순위별 요약 리스트
        List<ExpenseSimpleResponse> top3Expenses,
        long emotionTotalAmount, // 마음 당 총 소비건수
        long weeklyTotalCount, // 주간 총 소비개수
        long weeklyTotalAmount// 주간 총 소비금액

){}
