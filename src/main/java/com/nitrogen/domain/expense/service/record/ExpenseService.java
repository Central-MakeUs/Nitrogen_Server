package com.nitrogen.domain.expense.service.record;

import com.nitrogen.domain.expense.dto.ExpenseDetailsDTO;
import com.nitrogen.domain.expense.dto.ExpenseRemindRequestDTO;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.SubCategory;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.repository.SubCategoryRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExpenseService {

    private final CategoryRepository categoryRepository;
    private final SubCategoryRepository subCategoryRepository;
    private final UserRepository userRepository;
    private final ExpenseRepository expenseRepository;

    // 지출 기록 작성
    public long registerExpense(ExpenseDetailsDTO dto, Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        Category category = categoryRepository.findById(dto.getCategoryId())
                .orElseThrow(() -> new IllegalArgumentException("상위 카테고리가 존재하지 않습니다."));

        SubCategory subCategory = null;
        if (dto.getSubCategoryId() != null) {
            subCategory = subCategoryRepository.findById(dto.getSubCategoryId())
                    .orElseThrow(() -> new IllegalArgumentException("세부 카테고리가 존재하지 않습니다."));
        }

        if (subCategory != null && !subCategory.getParentCategory().getId().equals(category.getId())) {
            throw new IllegalArgumentException("선택한 세부 카테고리가 해당 상위 카테고리에 속하지 않습니다.");
        }

        Expense expense = Expense.builder()
                .amount(dto.getAmount())
                .expendedAt(dto.getExpendedAt())
                .category(category)
                .subCategory(subCategory)
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

        if (!expense.getUser().getUserId().equals(userId)) {
            throw new IllegalArgumentException("해당 지출에 대한 접근 권한이 없습니다.");
        }

        expense.updateEvaluation(dto.getEvaluationType());
        return expense.getId();
    }
}
