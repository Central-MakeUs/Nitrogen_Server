package com.nitrogen.domain.expense.dto.weeklyAndmonthly;

import java.util.List;
/*
월 + 주차별 open 상태 통합 API
*/
public record TotalOpenStatusResponse (
        int year,
        int month,
        long totalAmount,
        List<WeeklyOpenStatus> weeklyReports,
        boolean monthlyIsOpened
){
}
