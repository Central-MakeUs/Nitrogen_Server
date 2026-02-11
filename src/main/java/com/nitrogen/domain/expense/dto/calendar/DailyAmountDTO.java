package com.nitrogen.domain.expense.dto.calendar;

import java.time.LocalDate;

public record DailyAmountDTO(
        LocalDate date,
        Long dayAmount
) {}
