package com.nitrogen.global.auth.controller;

import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/onboarding")
@Tag(name = "Onboarding", description = "온보딩 관련 API")
@RequiredArgsConstructor
public class OnboardingController {

    private final OauthService oauthService;

    /**
     * 홈 온보딩
     */
    @PatchMapping("/home")
    public ApiResponse<String> completeHomeOnboarding(@AuthenticationPrincipal Long userId) {
        oauthService.finishOnboarding(userId, "HOME");
        return ApiResponse.onSuccess("홈 온보딩 완료");
    }
    /**
     * 카테고리 온보딩
     */
    @PatchMapping("/category")
    public ApiResponse<String> completeCategoryOnboarding(@AuthenticationPrincipal Long userId) {
        oauthService.finishOnboarding(userId, "CATEGORY");
        return ApiResponse.onSuccess("카테고리 온보딩 완료");
    }

    /**
     * 소비회고 온보딩
     */
    @PatchMapping("/remind")
    public ApiResponse<String> completeRemindOnboarding(@AuthenticationPrincipal Long userId) {
        oauthService.finishOnboarding(userId, "REMIND");
        return ApiResponse.onSuccess("소비회고 온보딩 완료");
    }
}
