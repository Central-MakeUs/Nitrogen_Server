package com.nitrogen.global.auth.controller;

import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth/apple")
@RequiredArgsConstructor
public class AppleAuthController {

    private final OauthService oauthService;

    @PostMapping("/callback")
    public ApiResponse<String> handleAppleNotification(@RequestParam("payload") String payload) {
        log.info("애플 서버 알림 수신 및 처리 시작");

        // 서비스에서 비즈니스 로직 처리 (유저 상태 변경 등)
        oauthService.handleAppleServerNotification(payload);

        // 성공 응답 반환
        return ApiResponse.onSuccess("Apple Server Notification Processed Successfully");
    }
    @Operation(summary = "애플 로그인 리다이렉트")
    @PostMapping("/redirect/apple")
    public void appleRedirect(@RequestParam("code") String code, HttpServletResponse response) throws Exception {
    }

}
