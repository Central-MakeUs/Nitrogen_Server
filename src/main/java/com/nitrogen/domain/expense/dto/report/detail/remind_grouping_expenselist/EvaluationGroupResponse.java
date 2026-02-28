package com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;

import java.util.List;

public record EvaluationGroupResponse(
        int stepNumber,             // 섹션 번호
        String evaluationTitle,     // 정말 만족했어요
        int groupCount,             // 3건의 소비
        long groupTotalAmount,      // 총 3,600원
        List<ExpenseItemResponse> expenses // 실제 지출 아이템들
) {}
