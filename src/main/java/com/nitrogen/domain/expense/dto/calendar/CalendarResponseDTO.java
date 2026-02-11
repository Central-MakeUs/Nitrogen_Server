package com.nitrogen.domain.expense.dto.calendar;

import java.util.List;

public record CalendarResponseDTO(
        Long totalAmount, // 월별 총금액
        List<DailyAmountDTO> dailyAmount // 일별 총금액
) {}
