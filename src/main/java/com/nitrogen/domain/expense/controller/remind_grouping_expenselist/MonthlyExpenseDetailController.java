package com.nitrogen.domain.expense.controller.remind_grouping_expenselist;

import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.MonthlyExpenseDetailResponse;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.service.report.remind_grouping_expenselist.MonthlyExpenseDetailService;
import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/monthly-reports")
public class MonthlyExpenseDetailController {

    private final MonthlyExpenseDetailService monthlyExpenseDetailService;

    @Operation(summary = "월간 리포트 - 회고별 소비 내역 상세 조회", description = "선택한 마음 항목에 해당하는 지출만 필터링한 뒤, 그 안에서 회고별로 소비 상세 내역을 조회합니다.")
    @GetMapping("/details")
    public ApiResponse<MonthlyExpenseDetailResponse> getMonthlyExpenseDetails(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam int year,
            @RequestParam int month,
            @RequestParam EmotionType emotionType
    ) {
        Long userId = userDetails.getUserId();

        MonthlyExpenseDetailResponse response = monthlyExpenseDetailService.getMonthlyExpenseDetailList(
                userId, year, month, emotionType
        );

        return ApiResponse.onSuccess(response);
    }
}
