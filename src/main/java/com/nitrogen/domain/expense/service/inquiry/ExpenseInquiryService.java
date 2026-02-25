package com.nitrogen.domain.expense.service.inquiry;

import com.nitrogen.domain.expense.dto.calendar.CalendarResponseDTO;
import com.nitrogen.domain.expense.dto.calendar.DailyAmountDTO;
import com.nitrogen.domain.expense.dto.expense.DailyExpenseResponseDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseListDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseResponseDTO;
import com.nitrogen.domain.expense.dto.report.summary.MonthlyReportSummaryResponse;
import com.nitrogen.domain.expense.dto.report.summary.WeeklyReportResponse;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExpenseInquiryService {

    private final UserRepository userRepository;
    private final ExpenseRepository expenseRepository;

    // 지출 기록 조회(일별)
    @Transactional(readOnly = true)
    public DailyExpenseResponseDTO inquiryExpense(LocalDate expendedAt, Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        LocalDate startOfMonth = expendedAt.withDayOfMonth(1);
        LocalDate endOfMonth = expendedAt.withDayOfMonth(expendedAt.lengthOfMonth());
        long monthlyTotal = expenseRepository.calculateMonthlyTotal(userId, startOfMonth, endOfMonth);
        LocalDate today = LocalDate.now();

        List<Expense> expenseList = expenseRepository.findAllByUserUserIdAndExpendedAtWithCategory(userId, expendedAt);
        boolean hasAnyExpense = !expenseList.isEmpty();

        long pendingCount = expenseList.stream()
                .filter(e -> e.getEvaluationType() == null)
                .count();

        String bannerMessage;
        String bannerSubMessage;

        if (!hasAnyExpense) {
            bannerMessage = String.format("%d월 %d일의 소비가 남겨지지 않았어요.",
                    expendedAt.getMonthValue(), expendedAt.getDayOfMonth());
            bannerSubMessage = "소비를 기록한 뒤 만족도를 남겨보세요";
        } else {
            bannerMessage = String.format("%d월 %d일의 소비, 지금은 어떤가요?",
                    expendedAt.getMonthValue(), expendedAt.getDayOfMonth());
            if (expendedAt.isEqual(today)) {
                bannerSubMessage = "오늘의 소비는 내일 돌아볼 수 있습니다";
            } else {
                bannerSubMessage = pendingCount > 0 ?
                        String.format("아직 돌아보지 않은 소비 %d건", pendingCount) : "모든 회고를 완료했어요!";
            }
        }

        List<ExpenseListDTO> dtos = expenseList.stream()
                .map(e -> ExpenseListDTO.builder()
                        .expenseId(e.getId())
                        .amount(e.getAmount())
                        .usageHistory(e.getUsageHistory())
                        .categoryName(e.getCategory().getName())
                        .categoryIconType(e.getCategory().getCategoryIconType())
                        .emotionType(e.getEmotionType())
                        .evaluationType(e.getEvaluationType())
                        .build())
                .collect(Collectors.toList());

        return DailyExpenseResponseDTO.builder()
                .date(expendedAt)
                .monthlyTotalAmount(monthlyTotal)
                .bannerMessage(bannerMessage)
                .bannerSubMessage(bannerSubMessage)
                .isRetrospectCompleted(pendingCount == 0)
                .hasAnyExpense(hasAnyExpense)
                .expenses(dtos)
                .build();
    }

    // 회고할 소비내역 조회(일별)
    @Transactional(readOnly = true)
    public List<ExpenseResponseDTO> getPendingRetrospectList(Long userId, LocalDate date) {
        List<Expense> expenses = expenseRepository.findAllByUserUserIdAndExpendedAtWithCategory(userId, date);

        return expenses.stream()
                .filter(expense -> expense.getEvaluationType() == null)
                .map(ExpenseResponseDTO::from)
                .collect(Collectors.toList());
    }

    // 월별 총액 날짜별 총액
    @Transactional(readOnly = true)
    public CalendarResponseDTO getExpenseCalendar(int year, int month, Long userId) {
        LocalDate start = LocalDate.of(year, month, 1);
        LocalDate end = start.withDayOfMonth(start.lengthOfMonth());

        long totalAmount = expenseRepository.calculateMonthlyTotal(userId, start, end);

        List<DailyAmountDTO> dailyAmount = expenseRepository.calculateDailyTotals(userId, start, end);

        return new CalendarResponseDTO(totalAmount, dailyAmount);
    }

    // 월별 총액 리스트
    @Transactional(readOnly = true)
    public List<MonthlyReportSummaryResponse> getMonthlyTotalList(Long userId) {
        List<String> monthsWithExpenses = expenseRepository.findDistinctMonthsByUserId(userId);
        LocalDate now = LocalDate.now();

        return monthsWithExpenses.stream()
                .map(monthStr -> {
                    LocalDate startOfMonth = LocalDate.parse(monthStr);
                    LocalDate endOfMonth = startOfMonth.withDayOfMonth(startOfMonth.lengthOfMonth());

                    long totalAmount = expenseRepository.calculateMonthlyTotal(userId, startOfMonth, endOfMonth);

                    LocalDate reportOpenDate = startOfMonth.plusMonths(1);
                    boolean isOpened = now.isAfter(reportOpenDate) || now.isEqual(reportOpenDate);

                    return new MonthlyReportSummaryResponse(
                            String.valueOf(startOfMonth.getMonthValue()),
                            totalAmount,
                            isOpened
                    );
                })
                .collect(Collectors.toList());
    }
}
