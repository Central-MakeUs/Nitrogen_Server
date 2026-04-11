package com.nitrogen.domain.expense.dto.report.detail;

import com.nitrogen.domain.expense.dto.report.summary.EmotionDetailSummary;
import com.nitrogen.domain.expense.dto.report.summary.EmotionSummary;
import com.nitrogen.domain.expense.dto.report.summary.EvaluationSummary;

import java.util.List;

public record MonthlyDetailReportResponse(

        String monthTitle, // 월간 범위 (예: 2026년 1월 분석 리포트)
        String monthStartDate, // 월 시작일 (yyyy.MM.dd)
        String monthEndDate, // 월 종료일 (yyyy.MM.dd)
        String emotionFeedbackMessage, // 마음항목 관점 평균만족도 문장(상단)
        EmotionSummary topEmotion, // 가장 많이 소비한 마음
        String evaluationFeedbackMessage, // 소비회고 관점 평균만족도 문장(하단)
        List<EvaluationSummary> evaluationSummaries, // 가장 많이 소비한 마음
        List<EmotionDetailSummary> emotionDetails, // 그아래로 전체 마음 순위별 요약 리스트(감정별 만족도 분포 포함)
        List<ExpenseSimpleResponse> top3Expenses,
        long emotionTotalAmount, // 마음 당 총 소비건수
        long monthlyTotalCount, // 월간 총 소비개수
        long monthlyTotalAmount// 월간 총 소비금액

){}
