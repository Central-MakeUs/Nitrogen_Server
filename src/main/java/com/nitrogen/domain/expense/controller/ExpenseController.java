package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.expense.DailyExpenseResponseDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseDetailsDTO;
import com.nitrogen.domain.expense.dto.expense.ExpenseRemindRequestDTO;
import com.nitrogen.domain.expense.service.inquiry.ExpenseInquiryService;
import com.nitrogen.domain.expense.service.record.ExpenseRecordService;
import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/expense")
@Tag(name = "Expense", description = "지출 기록 작성 및 조회")
public class ExpenseController {
    private final ExpenseRecordService expenseService;
    private final ExpenseInquiryService expenseInquiryService;

    // 지출기록 작성
    @Operation(summary = "지출 기록 작성", description = "유저가 하루일과동안 쓴 지출목록을 작성합니다.")
    @PostMapping("/record")
    public ApiResponse<Long> registerExpense(
            @RequestBody @Valid ExpenseDetailsDTO dto,
            @AuthenticationPrincipal CustomUserDetails userDetails){

        Long userId = userDetails.getUserId();
        Long savedExpenseId = expenseService.registerExpense(dto, userId);
        return ApiResponse.onSuccess(savedExpenseId);
    }

    // 소비기록 회고
    @Operation(summary = "소비기록 회고", description = "유저가 하루일과동안 쓴 지출기록에 소비회고를 추가적으로 남깁니다.")
    @PatchMapping("/remind")
    public ApiResponse<Long> remindExpense(@RequestBody ExpenseRemindRequestDTO dto, @AuthenticationPrincipal CustomUserDetails userDetails) {

        Long userId = userDetails.getUserId();
        Long updatedId = expenseService.remindExpense(dto, userId);
        return ApiResponse.onSuccess(updatedId);
    }
    
    // 지출기록 조회
    @Operation(summary = "일별 지출 내역 조회", description = "특정 날짜의 지출 내역과 월간 총액을 조회합니다.")
    @GetMapping("/daily")
    public ResponseEntity<DailyExpenseResponseDTO> getDailyExpense(
            @RequestParam int year,
            @RequestParam int month,
            @RequestParam int day,
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        Long userId = userDetails.getUserId();
        LocalDate targetDate = LocalDate.of(year, month, day);

        DailyExpenseResponseDTO response = expenseInquiryService.inquiryExpense(targetDate, userId);
        return ResponseEntity.ok(response);
    }

    // 지출 기록 수정
    @Operation(summary = "지출 기록 수정", description = "유저가 작성한 지출 기록을 수정합니다.")
    @PatchMapping("/update_record/{expenseId}")
    public ApiResponse<Long> updateExpense(
            @PathVariable Long expenseId,
            @RequestBody @Valid ExpenseDetailsDTO dto,
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        Long userId = userDetails.getUserId();
        Long updatedExpenseId = expenseService.updateExpense(expenseId, dto, userId);
        return ApiResponse.onSuccess(updatedExpenseId);
    }
}
