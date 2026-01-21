package com.nitrogen.domain.expense.service.report;

import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.temporal.WeekFields;
import java.util.Locale;

@Service
public class WeekCheck {
    public void getIsoWeek(LocalDate date) {
        // ISO-8601
        WeekFields weekFields = WeekFields.of(Locale.getDefault());

        int weekOfMonth = date.get(weekFields.weekOfMonth());
        int month = date.getMonthValue();
    }
}
