package com.nitrogen.domain.expense.dto;

import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class ExpenseRemindRequestDTO {
    private Long expenseId; // 이걸로 작성된 지출기록내용 끌어오기 가능
    private EvaluationType evaluationType;
}
