package com.nitrogen.domain.expense.dto.weeklyAndmonthly;

/*
주차별 묶음 항목용
*/
public record WeeklyOpenStatus(
        int week,
        boolean isOpened
) {
}
