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
//    private Long dailyTotalAmount;
    private List<ExpenseListDTO> expenses;
}
