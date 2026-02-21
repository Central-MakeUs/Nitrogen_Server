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

    @Operation(summary = "애플 로그인 체크", description = "애플 OAuth 코드를 받아 가입 여부를 확인합니다. 신규 유저라면 임시 토큰을, 기존 유저라면 서비스 토큰을 반환합니다.")
    @PostMapping("/login")
    public ApiResponse<AppleUserResponseDTO> appleLogin(
            @RequestParam("code") String code,
            @RequestParam(value = "platform", defaultValue = "ios") String platform) {

        AppleUserResponseDTO loginResult = oauthService.appleLoginOrCheck(code, platform);
        return ApiResponse.onSuccess(loginResult);
    }

    @Operation(summary = "애플 회원가입 완료", description = "약관 동의 후 임시 토큰을 전달받아 실제 회원가입(DB 저장)을 처리하고 서비스 토큰을 발급합니다.")
    @PostMapping("/signup")
    public ApiResponse<AppleUserResponseDTO> appleSignup(
            @RequestBody Map<String, String> body) {

        String registerToken = body.get("registerToken");

        AppleUserResponseDTO signupResult = oauthService.signUpApple(registerToken);
        return ApiResponse.onSuccess(signupResult);
    }

    // server to server
    @Operation(summary = "애플 서버 알림 처리", description = "애플 서버에서 전송된 알림을 처리합니다.")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @io.swagger.v3.oas.annotations.media.Content(
                    examples = @io.swagger.v3.oas.annotations.media.ExampleObject(
                            name = "애플 알림 예시",
                            value = "{\"signedPayload\": \"apple_signed_payload_sample\"}"
                    )
            )
    )
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
}
