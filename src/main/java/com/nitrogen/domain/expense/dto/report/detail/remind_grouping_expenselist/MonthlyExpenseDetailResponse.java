package com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist;

import java.util.List;

public record MonthlyExpenseDetailResponse(
        String monthTitle,         // 2026년 1월
        String emotionTitle,       // 홀린 듯한 소비 상세 내역
        int totalCount,            // 총 소비 8건
        long totalAmount,          // 총 9,999,000원
        List<EvaluationGroupResponse> evaluationGroups // 만족도별 그룹 리스트
) {}
