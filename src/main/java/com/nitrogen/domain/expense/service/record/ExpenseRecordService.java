package com.nitrogen.domain.expense.service.record;

import com.nitrogen.domain.expense.dto.expense.ExpenseDetailsDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseRemindRequestDTO;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

        Category category = categoryRepository.findById(dto.getCategoryId())
                .orElseThrow(() -> new IllegalArgumentException("카테고리가 존재하지 않습니다."));

        if(dto.getAmount() <= 0){
            throw new IllegalArgumentException("지출기록은 0보다 커야합니다.");
        }

        if (dto.getUsageHistory() == null || dto.getUsageHistory().trim().isEmpty()) {
            throw new IllegalArgumentException("사용처 기록이 비어있습니다.");
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
    public long remindExpense(ExpenseRemindRequestDTO dto, Long userId){
        Expense expense = expenseRepository.findById(dto.getExpenseId())
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 지출 기록입니다."));

        log.info("지출 주인 ID: " + expense.getUser().getUserId());
        log.info("요청 보낸 ID: " + userId);

        if (!expense.getUser().getUserId().equals(userId)) {
            throw new IllegalArgumentException("해당 지출에 대한 접근 권한이 없습니다.");
        }

        expense.updateEvaluation(dto.getEvaluationType());
        return expense.getId();
    }
}
