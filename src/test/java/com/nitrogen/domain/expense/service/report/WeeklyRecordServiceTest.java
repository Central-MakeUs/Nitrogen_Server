package com.nitrogen.domain.expense.service.report;

import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.repository.MonthlyReportReadRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WeeklyRecordServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    ExpenseRepository expenseRepository;
    @Mock
    MonthlyReportReadRepository monthlyReportReadRepository;
    @InjectMocks WeeklyRecordService weeklyRecordService;

    @Test
    void checkMonthlyReport_유저가_없으면_예외() {
        // given
        Long userId = 1L;
        when(userRepository.findById(userId))
                .thenReturn(Optional.empty());

        // when & then
        assertThrows(IllegalArgumentException.class, () ->
                weeklyRecordService.checkMonthlyReport(userId, 2025, 3));

    }

    @Test
    void checonthlyReport_이미_확인한_리포트면_저장하지_않음() {
        Long userId = 1L;
        User user = User.builder().userId(userId).build();

        when(userRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(monthlyReportReadRepository.existsByUserAndReportMonth(user, LocalDate.of(2026, 03, 1)))
                    .thenReturn(true);
        weeklyRecordService.checkMonthlyReport(userId, 2026, 3);
        verify(monthlyReportReadRepository, never()).save(any());
    }

    @Test
    void checkMonthlyReport_처음_확인하면_저장() {
        Long userId = 1L;
        User user = User.builder().userId(userId).build();

        when(userRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(monthlyReportReadRepository.existsByUserAndReportMonth(user, LocalDate.of(2026, 03, 1)))
                .thenReturn(false);
        weeklyRecordService.checkMonthlyReport(userId, 2026, 3);
        verify(monthlyReportReadRepository).save(any());
    }

}