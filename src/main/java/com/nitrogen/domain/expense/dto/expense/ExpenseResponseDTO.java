package com.nitrogen.domain.expense.dto.expense;

import com.nitrogen.domain.expense.entity.Expense;
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
    private String title;
    private String category;
    private Long amount;
    private String situation;
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
                .title(expense.getUsageHistory())
                .amount((long) expense.getAmount())
                .category(expense.getCategory().getName())
                .situation(expense.getEmotionType().name())
                .date(expense.getExpendedAt())
                .build();
    }
}
