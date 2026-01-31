package com.nitrogen.domain.expense.dto.expense;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

public class ExpenseResponseDTO {
    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IdResponse {
        private Long id;
    }
}
