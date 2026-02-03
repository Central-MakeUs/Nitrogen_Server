package com.nitrogen.global.auth.controller;

import com.nitrogen.global.apiPayload.ApiResponse;
import com.nitrogen.global.auth.service.kakao_apple.OauthService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth/apple")
@RequiredArgsConstructor
public class AppleAuthController {

    private final OauthService oauthService;

    @Operation(summary = "애플 로그인 및 회원가입")
    @PostMapping("/login")
    public ApiResponse<Map<String, Object>> appleLogin(@RequestParam("code") String code) {

        Map<String, Object> loginResult = oauthService.appleLoginOrSignup(code);
        return ApiResponse.onSuccess(loginResult);
    }

    // server to server
    @PostMapping("/callback")
    public ApiResponse<String> handleAppleNotification(
            @RequestBody Map<String, String> body
    ) {
        String payload = body.get("signedPayload");
        oauthService.handleAppleServerNotification(payload);
        return ApiResponse.onSuccess("OK");
    }

}
