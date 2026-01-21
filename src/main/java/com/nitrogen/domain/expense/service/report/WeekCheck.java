package com.nitrogen.domain.expense.service.report;

import java.time.LocalDate;
import java.time.temporal.WeekFields;
import java.util.Locale;

public class WeekCheck {
    public void getIsoWeek(LocalDate date) {
        // ISO-8601
        WeekFields weekFields = WeekFields.of(Locale.getDefault());

        int weekOfMonth = date.get(weekFields.weekOfMonth());
        int month = date.getMonthValue();
    }
}
