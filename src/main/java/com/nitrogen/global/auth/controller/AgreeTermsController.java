package com.nitrogen.global.auth.controller;

import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "인증/권한 API", description = "약관 동의 및 토큰 처리를 담당합니다.")
public class AgreeTermsController {
    private final OauthService oauthService;

    @Operation(summary = "약관 동의 완료 API", description = "로그인한 유저의 약관 동의 상태를 true로 변경합니다.")
    @PatchMapping("/terms")
    public ApiResponse<String> patchTerms(@AuthenticationPrincipal CustomUserDetails userDetails) {
        oauthService.agreeUserTerms(userDetails.getUserId());
        return ApiResponse.onSuccess("약관 동의 처리가 완료되었습니다.");
    }
}
