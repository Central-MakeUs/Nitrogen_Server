package com.nitrogen.global.auth.controller;

import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.dto.apple.AppleUserResponseDTO;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth/apple")
@RequiredArgsConstructor
public class AppleAuthController {

    private final OauthService oauthService;

    @Operation(summary = "애플 로그인 및 회원가입", description = "애플 OAuth 코드를 받아 로그인 또는 회원가입을 처리합니다.")
    @PostMapping("/login")
    public ApiResponse<AppleUserResponseDTO> appleLogin(
            @RequestParam("code") String code,
            @RequestParam(value = "platform", defaultValue = "ios") String platform) {

        AppleUserResponseDTO loginResult = oauthService.appleLoginOrSignup(code, platform);
        return ApiResponse.onSuccess(loginResult);
    }

    // server to server
    @Operation(summary = "애플 서버 알림 처리", description = "애플 서버에서 전송된 알림을 처리합니다.")
    @PostMapping("/callback")
    public ApiResponse<String> handleAppleNotification(
            @RequestBody Map<String, String> body
    ) {
        try {
            String signedPayload = body.get("signedPayload");
            if (signedPayload == null) {
                log.warn("signedPayload 누락");
                return ApiResponse.onSuccess("IGNORED");
            }

            oauthService.handleAppleServerNotification(signedPayload);
            return ApiResponse.onSuccess("OK");

        } catch (Exception e) {
            log.error("Apple Notification 처리 실패", e);
            return ApiResponse.onSuccess("IGNORED");
        }
    }

    // 약관동의
    @Operation(summary = "약관 동의 완료 API", description = "로그인한 유저의 약관 동의 상태를 true로 변경합니다.")
    @PatchMapping("/terms")
    public ApiResponse<String> patchTerms(@AuthenticationPrincipal CustomUserDetails userDetails) {
        oauthService.agreeUserTerms(userDetails.getUserId());
        return ApiResponse.onSuccess("약관 동의 처리가 완료되었습니다.");
    }

}
