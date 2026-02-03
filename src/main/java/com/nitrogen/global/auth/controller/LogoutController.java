package com.nitrogen.global.auth.controller;

import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Logout", description = "로그아웃 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class LogoutController {

    private final OauthService oauthService;

    @Operation(summary = "공통 로그아웃", description = "카카오/애플 로그인 방식에 관계없이 현재 사용자를 로그아웃 처리합니다.")
    @PostMapping("/logout")
    public ApiResponse<String> logout(Authentication authentication) {
        String identifier = authentication.getName();
        oauthService.logout(identifier);
        return ApiResponse.onSuccess("Logout Success");
    }
}