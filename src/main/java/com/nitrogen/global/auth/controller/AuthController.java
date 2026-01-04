package com.nitrogen.global.auth.controller;

import com.nitrogen.global.auth.service.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth/kakao")
@Tag(name = "Auth", description = "카카오 소셜 로그인 API")
public class AuthController {
    private final OauthService oauthService;

    @Operation(summary = "카카오 로그인 콜백", description = "카카오 인가 코드를 통해 로그인을 진행하고 JWT를 발급합니다.")
    @GetMapping("/callback")
    public ResponseEntity<?> kakaoCallback(@RequestParam("code") String code) {
        log.info("카카오 로그인 콜백 요청 - 인가 코드: {}", code);

        Map<String, String> tokens = oauthService.loginOrSignup(code);
        return ResponseEntity.ok(tokens);
    }
}
