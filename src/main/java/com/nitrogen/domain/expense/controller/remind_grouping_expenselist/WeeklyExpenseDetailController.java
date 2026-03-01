package com.nitrogen.domain.expense.controller.remind_grouping_expenselist;

import com.nitrogen.domain.expense.dto.report.detail.remind_grouping_expenselist.WeeklyExpenseDetailResponse;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.service.report.remind_grouping_expenselist.WeeklyExpenseDetailService;
import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/weekly-reports")
public class WeeklyExpenseDetailController {

    private final WeeklyExpenseDetailService weeklyExpenseDetailService;

    @Operation(summary = "주간 리포트 - 회고별 소비 내역 상세 조회", description = "선택한 마음 항목에 해당하는 지출만 필터링한 뒤, 그 안에서 회고별로 소비 상세 내역을 조회합니다.")
    @GetMapping("/details")
    public ApiResponse<WeeklyExpenseDetailResponse> getWeeklyExpenseDetails(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end,
            @RequestParam String weekRange,
            @RequestParam EmotionType emotionType
    ) {
        Long userId = userDetails.getUserId();

        WeeklyExpenseDetailResponse response = weeklyExpenseDetailService.getWeeklyExpenseDetailList(
                userId, start, end, weekRange, emotionType
        );

        return ApiResponse.onSuccess(response);
    }
}
