package com.nitrogen.global.auth.controller;

import com.nitrogen.domain.user.dto.UserResponseDTO;
import com.nitrogen.domain.user.entity.CustomUserDetails;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.apiPayload.code.status.ErrorStatus;
import com.nitrogen.global.apiPayload.exception.UserHandler;
import com.nitrogen.global.auth.dto.AuthResponse;
import com.nitrogen.global.auth.security.TokenProvider;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Tag(name = "Auth", description = "인증 및 계정 관리 API")
public class KakaoAuthController {
    private final OauthService oauthService;
    private final TokenProvider tokenProvider;

    @Operation(summary = "카카오 로그인/체크", description = "카카오 토큰으로 기존 유저인지 확인한다. 신규 유저면 newUser: true와 임시 토큰을 반환한다.")
    @PostMapping("/kakao/login")
    public ApiResponse<AuthResponse> kakaoLogin(
            @RequestBody Map<String, Object> body, HttpServletResponse response) {

        String kakaoAccessToken = (String) body.get("accessToken");
        AuthResponse authResponse = oauthService.kakaoLoginOrCheck(kakaoAccessToken);

//        if (!authResponse.isNewUser() && authResponse.getRefreshToken() != null) {
//            response.addHeader("RefreshToken", "Bearer " + authResponse.getRefreshToken());
//            authResponse.setRefreshToken(null);
//        }

        return ApiResponse.onSuccess(authResponse);
    }

    @Operation(summary = "카카오 회원가입", description = "임시 토큰을 이용해 카카오 가입을 완료하고 정식 JWT를 발급한다.")
    @PostMapping("/kakao/signup")
    public ApiResponse<AuthResponse> kakaoSignup(
            @RequestBody Map<String, Object> body, HttpServletResponse response) {

        String registerToken = (String) body.get("registerToken");
        AuthResponse authResponse = oauthService.signUpKakao(registerToken);

        if (authResponse.getRefreshToken() != null) {
            response.addHeader("RefreshToken", "Bearer " + authResponse.getRefreshToken());
            authResponse.setRefreshToken(null);
        }

        return ApiResponse.onSuccess(authResponse);
    }

    @Operation(summary = "회원 탈퇴", description = "현재 로그인한 유저의 정보를 삭제한다.")
    @DeleteMapping("/withdraw")
    public ApiResponse<String> withdraw(@AuthenticationPrincipal UserDetails userDetails, HttpServletResponse response) {
        oauthService.withdraw(((CustomUserDetails) userDetails).getUserId());

        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        log.info("유저 탈퇴 완료 (Identifier: {})", userDetails.getUsername());
        return ApiResponse.onSuccess("회원 탈퇴가 완료되었습니다.");
    }

    /**
     * 토큰 재발급
     */
    @Operation(summary = "토큰 재발급 API", description = "헤더의 RefreshToken(Bearer 형기)으로 토큰을 재발급합니다.")
    @PostMapping("/reissue")
    public ApiResponse<UserResponseDTO.TokenReissueResultDTO> reissue(
            @RequestHeader("RefreshToken") String refreshToken) {

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new UserHandler(ErrorStatus.INVALID_TOKEN);
        }

        String pureToken = refreshToken.startsWith("Bearer ") ?
                refreshToken.substring(7).trim() : refreshToken.trim();

        return ApiResponse.onSuccess(oauthService.reissueToken(pureToken));
    }
}


// 쿠키 방식 백업
//        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
//                .httpOnly(true)
//                .secure(true)
//                .path("/")
//                .maxAge(7 * 24 * 60 * 60)
//                .sameSite("Lax")
//                .build();

//        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
