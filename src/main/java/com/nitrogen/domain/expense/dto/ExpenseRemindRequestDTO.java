package com.nitrogen.domain.expense.dto;

import com.nitrogen.domain.expense.entity.enums.EvaluationType;

public class ExpenseRemindRequestDTO {
    private Long expenseId; // 이걸로 작성된 지출기록내용 끌어오기 가능
    private EvaluationType evaluationType;
}
