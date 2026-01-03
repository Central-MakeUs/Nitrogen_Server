package com.nitrogen.global.auth.service;

import com.nitrogen.global.auth.dto.KakaoUserInfo;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.entity.repository.UserRepository;
import com.nitrogen.global.auth.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OauthService {
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${kakao.client-id}")
    private String clientId;

    @Value("${kakao.client-secret}")
    private String clientSecret;

    @Value("${kakao.redirect-uris}")
    private String redirectUri;

    public String loginOrSignup(String code) {

        String kakaoAccessToken = getKakaoAccessToken(code);
        KakaoUserInfo userInfo = getKakaoUserInfo(kakaoAccessToken);

        User user = userRepository.findBySocialId(userInfo.getProviderId())
                .orElseGet(() -> userRepository.save(User.builder()
                        .socialId(userInfo.getProviderId())
                        .email(userInfo.getEmail())
                        .nickname(userInfo.getName())
                        .provider(userInfo.getProvider())
                        .build()));

        return tokenProvider.createToken(user.getSocialId());
    }

    private String getKakaoAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("code", code);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    "https://kauth.kakao.com/oauth/token", request, Map.class);

            Map<String, Object> responseBody = response.getBody();
            if (responseBody == null || !responseBody.containsKey("access_token")) {
                throw new RuntimeException("카카오 응답에 액세스 토큰이 없습니다.");
            }

            return (String) responseBody.get("access_token");
        } catch (Exception e) {
            log.error("카카오 토큰 발급 실패: {}", e.getMessage());
            throw new RuntimeException("카카오 인증 실패: " + e.getMessage());
        }
    }

    private KakaoUserInfo getKakaoUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    "https://kapi.kakao.com/v2/user/me",
                    HttpMethod.GET,
                    request,
                    Map.class
            );
            return new KakaoUserInfo(response.getBody());
        } catch (Exception e) {
            log.error("카카오 사용자 정보 조회 실패: {}", e.getMessage());
            throw new RuntimeException("카카오 정보 조회 실패");
        }
    }
}
