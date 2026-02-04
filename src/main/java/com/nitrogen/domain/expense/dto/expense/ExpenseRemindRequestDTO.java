package com.nitrogen.domain.expense.dto.expense;

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
    private Long expenseId;
    private EvaluationType evaluationType;
}
