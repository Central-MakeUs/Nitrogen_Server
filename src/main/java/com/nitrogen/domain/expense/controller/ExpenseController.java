package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.ExpenseDetailsDTO;
import com.nitrogen.domain.expense.dto.ExpenseRemindRequestDTO;
import com.nitrogen.domain.expense.service.record.ExpenseService;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/expense")
@Tag(name = "Expense", description = "지출 기록 작성 및 조회")
public class ExpenseController {
    private final ExpenseService expenseService;

    // 지출기록 작성
    @Operation(summary = "지출 기록 작성", description = "유저가 하루일과동안 쓴 지출목록을 작성합니다.")
    @PostMapping("/record")
    public ApiResponse<Long> registerExpense(
            @RequestBody @Valid ExpenseDetailsDTO dto,
            @RequestParam("userId") Long userId){
        Long savedExpenseId = expenseService.registerExpense(dto, userId);
        return ApiResponse.onSuccess(savedExpenseId);
    }

    // 소비기록 회고
    @Operation(summary = "소비기록 회고", description = "유저가 하루일과동안 쓴 지출기록에 소비회고를 추가적으로 남깁니다.")
    @PatchMapping("/remind")
    public ApiResponse<Long> remindExpense(@RequestBody ExpenseRemindRequestDTO dto, @RequestParam("userId") Long userId) {
        Long updatedId = expenseService.remindExpense(dto, userId);
        return ApiResponse.onSuccess(updatedId);
    }
    
    // 지출기록 조회
}
