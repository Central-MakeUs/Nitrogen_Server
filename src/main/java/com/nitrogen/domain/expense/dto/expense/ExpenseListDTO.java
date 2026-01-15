package com.nitrogen.domain.expense.dto.expense;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Builder
@AllArgsConstructor
public class ExpenseListDTO {
    private Long expenseId;
    private Integer amount;
    private String usageHistory;
    private String categoryName;
    private EmotionType emotionType;
    private EvaluationType evaluationType;
}