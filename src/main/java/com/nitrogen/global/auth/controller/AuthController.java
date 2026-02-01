package com.nitrogen.global.auth.controller;

import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.dto.AuthResponse;
import com.nitrogen.global.auth.service.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Tag(name = "Auth", description = "인증 및 계정 관리 API")
public class AuthController {
    private final OauthService oauthService;

    @Operation(summary = "카카오 로그인 콜백", description = "카카오 인가 코드를 통해 로그인을 진행하고 JWT 및 유저 정보를 반환한다.")
    @GetMapping("/kakao/callback")
    public ApiResponse<AuthResponse> kakaoCallback(
            @RequestParam("code") String code,
            HttpServletRequest request,
            HttpServletResponse response) { // 응답 헤더에 쿠키를 추가하기 위해 response 객체 필요

        String currentUri = request.getHeader("Referer");
        if (currentUri == null) {
            currentUri = request.getRequestURL().toString();
        }

        Map<String, Object> result = oauthService.loginOrSignup(code, currentUri);

        User user = (User) result.get("user");
        String accessToken = (String) result.get("accessToken");
        String refreshToken = (String) result.get("refreshToken");

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)             // 클라이언트 사이드 스크립트에서 접근 불가 (XSS 방어)
                .secure(true)               // HTTPS 프로토콜에서만 전송
                .path("/")                  // 애플리케이션 전체 경로에서 유효
                .maxAge(7 * 24 * 60 * 60)   // 쿠키 만료 시간 (7일)
                .sameSite("None")           // 크로스 사이트 요청 허용 (프론트/백 도메인 불일치 대응)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .user(AuthResponse.UserInfo.builder()
                        .userId(user.getUserId())
                        .nickname(user.getNickname())
                        .type(user.getProvider())
                        .build())
                .build();

        return ApiResponse.onSuccess(authResponse);
    }

    @Operation(summary = "oauth 애플 로그인 리다이렉트")
    @PostMapping("/redirect/apple")
    public void appleRedirect(@RequestParam("code") String code, HttpServletResponse response) throws Exception {
    }

    @Operation(summary = "회원 탈퇴", description = "현재 로그인한 유저의 정보를 삭제한다.")
    @DeleteMapping("/withdraw")
    public ApiResponse<String> withdraw(@AuthenticationPrincipal UserDetails userDetails) {
        oauthService.withdraw(userDetails.getUsername());
        log.info("유저 탈퇴 완료: {}", userDetails.getUsername());
        return ApiResponse.onSuccess("회원 탈퇴가 완료되었습니다.");
    }
}
