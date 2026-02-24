package com.nitrogen.domain.alert.controller;

import com.nitrogen.domain.alert.dto.AlertResponseDTO;
import com.nitrogen.domain.alert.service.AlertService;
import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
@Tag(name = "Alert", description = "알림 API")
public class AlertController {

    private final AlertService alertService;

    @Operation(summary = "알림 목록 조회", description = "유저의 알림 목록을 최신순으로 조회합니다.")
    @GetMapping
    public ApiResponse<List<AlertResponseDTO>> getAlertList(
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        List<AlertResponseDTO> responses = alertService.getAlertList(userDetails.getUser());
        return ApiResponse.onSuccess(responses);
    }

    @Operation(summary = "알림 개별 읽음 처리", description = "특정 알림을 읽음 상태로 변경합니다.")
    @PatchMapping("/{alertId}/read")
    public ApiResponse<String> markAsRead(
            @PathVariable Long alertId,
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        alertService.markAsRead(alertId, userDetails.getUser());
        return ApiResponse.onSuccess("알림이 읽음 처리되었습니다.");
    }

//    @Operation(summary = "알림 전체 읽음 처리", description = "읽지 않은 모든 알림을 읽음 상태로 변경합니다.")
//    @PatchMapping("/read-all")
//    public ApiResponse<String> markAllAsRead(
//            @AuthenticationPrincipal CustomUserDetails userDetails) {
//
//        alertService.markAllAsRead(userDetails.getUser());
//        return ApiResponse.onSuccess("모든 알림이 읽음 처리되었습니다.");
//    }
}