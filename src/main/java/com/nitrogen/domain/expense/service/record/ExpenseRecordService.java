package com.nitrogen.domain.expense.service.record;

import com.nitrogen.domain.alert.dto.FCMRequestDTO;
import com.nitrogen.domain.alert.entity.enums.AlertType;
import com.nitrogen.domain.alert.service.FcmService;
import com.nitrogen.domain.expense.dto.expense.ExpenseDetailsDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseRemindRequestDTO;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import com.nitrogen.global.apiPayload.code.status.ErrorStatus;
import com.nitrogen.global.apiPayload.exception.GeneralException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
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
    private final FcmService fcmService;

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");

    // 지출 기록 작성
    public long registerExpense(ExpenseDetailsDTO dto, Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new GeneralException(ErrorStatus.USER_NOT_FOUND));

        Category category = categoryRepository
                .findByIdAndUser_UserId(dto.getCategoryId(), userId)
                .orElseThrow(() -> new GeneralException(ErrorStatus.CATEGORY_NOT_FOUND));

        if(dto.getAmount() <= 0){
            throw new GeneralException(ErrorStatus.EXPENSE_INVALID_AMOUNT);
        }

        if (dto.getUsageHistory() == null || dto.getUsageHistory().trim().isEmpty()) {
            throw new GeneralException(ErrorStatus.EXPENSE_USAGE_EMPTY);
        }

        if (dto.getExpendedAt().isAfter(LocalDate.now(KST))) {
            throw new GeneralException(ErrorStatus.EXPENSE_FUTURE_DATE);
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
        category.updateTimestamp();

        log.info("지출 기록 완료: ID={}, 금액={}", saved.getId(), saved.getAmount());
        return saved.getId();
    }

    // 소비 회고
    public List<Long> remindExpenses(List<ExpenseRemindRequestDTO> dtos, Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new GeneralException(ErrorStatus.USER_NOT_FOUND));

        List<Long> updatedIds = dtos.stream()
                .map(dto ->{
                    Expense expense = expenseRepository.findById(dto.getExpenseId())
                            .orElseThrow(() -> new GeneralException(ErrorStatus.EXPENSE_NOT_FOUND));

                    if (!expense.getUser().getUserId().equals(userId)) {
                        throw new GeneralException(ErrorStatus.EXPENSE_FORBIDDEN);
                    }

                    if (!expense.getExpendedAt().isBefore(LocalDate.now(KST))) {
                        throw new GeneralException(ErrorStatus.EXPENSE_REMIND_TOO_EARLY);
                    }
                    expense.updateEvaluation(dto.getEvaluationType());
                    return expense.getId();
                })
                .collect(Collectors.toList());

        if (expenseRepository.existsByEvaluationTypeIsNullAndUserAndExpendedAtBefore(user, LocalDate.now(KST))) {
            String targetId = user.getSocialId() != null ? user.getSocialId() : user.getAppleSub();

            String yesterday = LocalDate.now(KST)
                    .minusDays(1)
                    .format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));

            String redirectUrl = "/review/" + yesterday;

            fcmService.sendAndSaveAlert(new FCMRequestDTO(
                    targetId,
                    "돌아보기 알림",
                    "아직 돌아보지 않은 소비가 있어요!",
                    redirectUrl
            ), AlertType.RETROSPECT);
        }
        return updatedIds;
    }

    // 지출 기록 수정
    @Transactional
    public Long updateExpense(Long expenseId, ExpenseDetailsDTO dto, Long userId) {
        Expense expense = expenseRepository.findById(expenseId)
                .orElseThrow(() -> new GeneralException(ErrorStatus.EXPENSE_NOT_FOUND));

        if (!expense.getUser().getUserId().equals(userId)) {
            throw new GeneralException(ErrorStatus.EXPENSE_FORBIDDEN);
        }

        Category category = categoryRepository
                .findByIdAndUser_UserId(dto.getCategoryId(), userId)
                .orElseThrow(() -> new GeneralException(ErrorStatus.CATEGORY_NOT_FOUND));

        expense.updateExpenseRecord(dto.getAmount(), dto.getUsageHistory(), dto.getExpendedAt(), category);
        category.updateTimestamp();

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
