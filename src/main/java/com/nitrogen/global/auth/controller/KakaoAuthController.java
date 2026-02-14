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

    @Operation(summary = "카카오 로그인", description = "프론트에서 받은 카카오 유저 정보를 통해 로그인을 진행하고 JWT 및 유저 정보를 반환한다.")
    @PostMapping("/kakao/login")
    public ApiResponse<AuthResponse> kakaoLogin(
            @RequestBody Map<String, Object> kakaoAttributes,
            HttpServletRequest request,
            HttpServletResponse response) {

        log.info("카카오 로그인 요청 수신");

        Map<String, Object> result = oauthService.loginOrSignup(kakaoAttributes);

        User user = (User) result.get("user");
        String accessToken = (String) result.get("accessToken");
        String refreshToken = (String) result.get("refreshToken");

        // 쿠키 방식 백업
//        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
//                .httpOnly(true)
//                .secure(true)
//                .path("/")
//                .maxAge(7 * 24 * 60 * 60)
//                .sameSite("Lax")
//                .build();

//        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(AuthResponse.UserInfo.builder()
                        .userId(user.getUserId())
                        .nickname(user.getNickname())
                        .type(user.getProvider())
                        .build())
                .build();

        return ApiResponse.onSuccess(authResponse);
    }

    @Operation(summary = "회원 탈퇴", description = "현재 로그인한 유저의 정보를 삭제한다.")
    @DeleteMapping("/withdraw")
    public ApiResponse<String> withdraw(@AuthenticationPrincipal UserDetails userDetails, HttpServletResponse response) {
        oauthService.withdraw(userDetails.getUsername());

        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        log.info("유저 탈퇴 완료: {}", userDetails.getUsername());
        return ApiResponse.onSuccess("회원 탈퇴가 완료되었습니다.");
    }

    /**
     * 토큰 재발급
     */
    @Operation(summary = "토큰 재발급 API", description = "리프레시 토큰으로 액세스 토큰을 재발급하는 API입니다.")
    @PostMapping("/reissue")
    public ApiResponse<UserResponseDTO.TokenReissueResultDTO> reissue(
            HttpServletRequest request) {

        String refreshToken = null;
        Cookie[] cookies = request.getCookies();
        System.out.println("쿠키 배열 존재 여부: " + (request.getCookies() != null));
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    System.out.println("쿠키 이름: " + cookie.getName() + ", 값: " + cookie.getValue());
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if(refreshToken == null){
            throw new UserHandler(ErrorStatus.INVALID_TOKEN);
        }
        return ApiResponse.onSuccess(oauthService.reissueToken(refreshToken));
    }

    // 약관동의
    @Operation(summary = "약관 동의 완료 API", description = "로그인한 유저의 약관 동의 상태를 true로 변경합니다.")
    @PatchMapping("/terms")
    public ApiResponse<String> patchTerms(@AuthenticationPrincipal CustomUserDetails userDetails) {
        oauthService.agreeUserTerms(userDetails.getUserId());
        return ApiResponse.onSuccess("약관 동의 처리가 완료되었습니다.");
    }
}
