package com.nitrogen.domain.expense.dto.report.detail;

import com.nitrogen.domain.expense.dto.report.summary.EmotionSummary;
import com.nitrogen.domain.expense.entity.Expense;

import java.util.List;

public record WeeklyDetailReportResponse(

        String weekRange, // 주간 범위
        String headerAvarageEvaluation,// 평균점수에 해당하는 문장(상단)
        EmotionSummary topEmotion, // 가장 많이 소비한 마음
        String inAvarageEvaluation, // 평균점수에 해당하는 문장(하단 회색박스)
        List<EvaluationSummary> evaluationSummaries, // 가장 많이 소비한 마음
        List<ExpenseSimpleResponse> top3Expenses,
        long emotionTotalAmount, // 마음 당 총 소비건수
        long weeklyTotalCount, // 주간 총 소비개수
        long weeklyTotalAmount// 주간 총 소비금액

){}
