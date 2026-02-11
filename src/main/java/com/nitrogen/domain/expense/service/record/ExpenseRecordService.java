package com.nitrogen.domain.expense.service.record;

import com.nitrogen.domain.expense.dto.expense.ExpenseDetailsDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseListDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseRemindRequestDTO;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.service.inquiry.ExpenseInquiryService;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import com.nitrogen.global.apiPayload.code.status.ErrorStatus;
import com.nitrogen.global.apiPayload.exception.GeneralException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ExpenseRecordService {

    private final CategoryRepository categoryRepository;
    private final UserRepository userRepository;
    private final ExpenseRepository expenseRepository;

    // 지출 기록 작성
    public long registerExpense(ExpenseDetailsDTO dto, Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        Category category = categoryRepository
                .findByIdAndUser_UserId(dto.getCategoryId(), userId)
                .orElseThrow(() -> new IllegalArgumentException("카테고리가 존재하지 않거나 접근 권한이 없습니다."));

        if(dto.getAmount() <= 0){
            throw new IllegalArgumentException("지출기록은 0보다 커야합니다.");
        }

        if (dto.getUsageHistory() == null || dto.getUsageHistory().trim().isEmpty()) {
            throw new IllegalArgumentException("사용처 기록이 비어있습니다.");
        }

        if (dto.getExpendedAt().isAfter(java.time.LocalDate.now(java.time.ZoneId.of("Asia/Seoul")))) {
            throw new IllegalArgumentException("미래 날짜로 소비 기록을 작성할 수 없습니다.");
        }

        Expense expense = Expense.builder()
                .amount(dto.getAmount())
                .expendedAt(dto.getExpendedAt())
                .category(category)
                .usageHistory(dto.getUsageHistory())
                .emotionType(dto.getEmotionType())
                .user(user)
                .build();
        Expense saved = expenseRepository.save(expense);

        log.info("지출 기록 완료: ID={}, 금액={}", saved.getId(), saved.getAmount());
        return saved.getId();
    }

    // 소비 회고
    public List<Long> remindExpenses(List<ExpenseRemindRequestDTO> dtos, Long userId){
       return dtos.stream()
               .map(dto ->{
                   Expense expense = expenseRepository.findById(dto.getExpenseId())
                           .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 지출 기록입니다. ID: " + dto.getExpenseId()));

                   if (!expense.getUser().getUserId().equals(userId)) {
                       throw new IllegalArgumentException("해당 지출에 대한 접근 권한이 없습니다. ID: " + dto.getExpenseId());
                   }

                   if (!expense.getExpendedAt().isBefore(java.time.LocalDate.now(java.time.ZoneId.of("Asia/Seoul")))) {
                       throw new IllegalArgumentException("소비 회고는 기록한 다음 날부터 가능합니다. ID: " + dto.getExpenseId());
                   }
                   expense.updateEvaluation(dto.getEvaluationType());
                   return expense.getId();
               })
               .collect(Collectors.toList());
    }

    // 지출 기록 수정
    @Transactional
    public Long updateExpense(Long expenseId, ExpenseDetailsDTO dto, Long userId) {
        Expense expense = expenseRepository.findById(expenseId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 지출 기록입니다."));

        if (!expense.getUser().getUserId().equals(userId)) {
            throw new IllegalArgumentException("해당 지출에 대한 접근 권한이 없습니다.");
        }

        Category category = categoryRepository
                .findByIdAndUser_UserId(dto.getCategoryId(), userId)
                .orElseThrow(() -> new IllegalArgumentException("카테고리가 존재하지 않거나 접근 권한이 없습니다."));

        expense.updateExpenseRecord(dto.getAmount(), dto.getUsageHistory(), dto.getExpendedAt(), category);

        return expense.getId();
    }

    // 지출 기록 삭제
    @Transactional
    public void deleteExpense(Long expenseId, Long userId) {
        Expense expense = expenseRepository.findById(expenseId)
                .orElseThrow(() -> new GeneralException(ErrorStatus.EXPENSE_NOT_FOUND));

        if (!expense.getUser().getUserId().equals(userId)) {
            throw new GeneralException(ErrorStatus.EXPENSE_FORBIDDEN);
        }
        expenseRepository.delete(expense);
    }

}
