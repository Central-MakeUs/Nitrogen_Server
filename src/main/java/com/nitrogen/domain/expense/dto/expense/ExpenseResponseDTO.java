package com.nitrogen.domain.expense.dto.expense;

import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.CategoryIconType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ExpenseResponseDTO {

    private Long expenseId;
    private LocalDate date;
    private CategoryIconType categoryIconType;
    private String usageHistory;
    private String categoryName;
    private Long amount;
    private String emotionType;

    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IdResponse {
        private Long id;
    }

    public static ExpenseResponseDTO from(Expense expense) {
        return ExpenseResponseDTO.builder()
                .expenseId(expense.getId())
                .date(expense.getExpendedAt())
                .categoryIconType(expense.getCategory().getCategoryIconType())
                .usageHistory(expense.getUsageHistory())
                .categoryName(expense.getCategory().getName())
                .amount((long) expense.getAmount())
                .emotionType(expense.getEmotionType().name())
                .build();
    }
}
