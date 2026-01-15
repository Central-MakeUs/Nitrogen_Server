package com.nitrogen.domain.expense.service.inquiry;

import com.nitrogen.domain.expense.dto.expense.DailyExpenseResponseDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseListDTO;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExpenseInquiryService {

    private final UserRepository userRepository;
    private final ExpenseRepository expenseRepository;

    // 지출 기록 조회(일별)
    public DailyExpenseResponseDTO inquiryExpense(LocalDate expendedAt, Long userId){

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        LocalDate startOfMonth = expendedAt.withDayOfMonth(1);
        LocalDate endOfMonth = expendedAt.withDayOfMonth(expendedAt.lengthOfMonth());
        long monthlyTotal = expenseRepository.calculateMonthlyTotal(userId, startOfMonth, endOfMonth);

        List<Expense> expenseList = expenseRepository.findAllByUserIdAndExpendedAt(userId, expendedAt);

        List<ExpenseListDTO> dtos = expenseList.stream()
                .map(e -> ExpenseListDTO.builder()
                        .expenseId(e.getId())
                        .amount(e.getAmount())
                        .usageHistory(e.getUsageHistory())
                        .categoryName(e.getCategory().getName())
                        .emotionType(e.getEmotionType())
                        .evaluationType(e.getEvaluationType())
                        .build())
                .collect(Collectors.toList());

        return DailyExpenseResponseDTO.builder()
                .date(expendedAt)
                .monthlyTotalAmount(monthlyTotal)
                .expenses(dtos)
                .build();
    }

}
