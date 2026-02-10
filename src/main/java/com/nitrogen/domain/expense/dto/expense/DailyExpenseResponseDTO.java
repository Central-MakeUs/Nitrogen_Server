package com.nitrogen.domain.expense.dto.expense;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;
import java.util.List;

@Getter
@Builder
@AllArgsConstructor
public class DailyExpenseResponseDTO {
    private LocalDate date;
    private Long monthlyTotalAmount;

    // 배너 메시지
    private String bannerMessage;
    private String bannerSubMessage;
    private boolean isRetrospectCompleted;

    private boolean hasAnyExpense;

    private List<ExpenseListDTO> expenses;
}
