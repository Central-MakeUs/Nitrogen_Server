package com.nitrogen.domain.alert.controller;

import com.nitrogen.domain.alert.dto.AlertResponseDTO;
import com.nitrogen.domain.alert.service.AlertService;
import com.nitrogen.domain.alert.service.FcmService;
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
@Tag(name = "Alert", description = "푸쉬알림 API")
public class AlertController {

    private final FcmService fcmService;
    private final AlertService alertService;

    @Operation(summary = "FCM 토큰 업데이트(등록)", description = "로그인 직후 기기의 FCM 토큰을 서버에 등록합니다.")
    @PatchMapping("/fcm-token")
    public ApiResponse<String> updateFcmToken(
            @RequestParam String fcmToken,
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        fcmService.updateFcmToken(userDetails.getUser(), fcmToken);
        return ApiResponse.onSuccess("FCM 토큰이 성공적으로 등록되었습니다.");
    }

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
    @Operation(summary = "알림 수신 동의 상태 변경", description = "유저의 알림 수신 허용/거부 상태를 업데이트합니다.")
    @PatchMapping("/settings")
    public ApiResponse<String> updateAlarmStatus(
            @RequestParam boolean isAlarmOn,
            @AuthenticationPrincipal CustomUserDetails userDetails){
        alertService.updateAlarmStatus(userDetails.getUser(), isAlarmOn);

        String status = isAlarmOn ? "허용" : "거부";
        return ApiResponse.onSuccess("알림 수신 상태가 " + status + "로 변경되었습니다.");
    }

    @Operation(summary = "읽지 않은 알림 존재 여부 확인", description = "빨간 점(Badge) 표시 여부")
    @GetMapping("/unread-status")
    public ApiResponse<Boolean> hasUnreadAlerts(
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        boolean hasUnread = alertService.existsUnreadAlerts(userDetails.getUser());
        return ApiResponse.onSuccess(hasUnread);
    }
}