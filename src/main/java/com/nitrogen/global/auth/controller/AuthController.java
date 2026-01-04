package com.nitrogen.global.auth.controller;

import com.nitrogen.global.auth.service.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth") // 경로를 /api/auth로 통일
@Tag(name = "Auth", description = "인증 및 계정 관리 API")
public class AuthController {
    private final OauthService oauthService;

    @Operation(summary = "카카오 로그인 콜백", description = "카카오 인가 코드를 통해 로그인을 진행하고 JWT를 발급합니다.")
    @GetMapping("/kakao/callback")
    public ResponseEntity<?> kakaoCallback(@RequestParam("code") String code) {
        log.info("카카오 로그인 콜백 요청 - 인가 코드: {}", code);

        Map<String, String> tokens = oauthService.loginOrSignup(code);
        return ResponseEntity.ok(tokens);
    }

    @Operation(summary = "회원 탈퇴", description = "현재 로그인한 유저의 정보를 삭제합니다.")
    @DeleteMapping("/withdraw")
    public ResponseEntity<Void> withdraw(@AuthenticationPrincipal UserDetails userDetails) {
        oauthService.withdraw(userDetails.getUsername());
        log.info("유저 탈퇴 완료: {}", userDetails.getUsername());
        return ResponseEntity.noContent().build();
    }
}
