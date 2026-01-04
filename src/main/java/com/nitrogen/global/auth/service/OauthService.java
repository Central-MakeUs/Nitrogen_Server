package com.nitrogen.global.auth.service;

import com.nitrogen.domain.user.repository.UserRepository;
import com.nitrogen.global.auth.dto.KakaoUserInfo;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.auth.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OauthService {
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${kakao.client_id}")
    private String clientId;

    @Value("${kakao.client_secret}")
    private String clientSecret;

    // 탈퇴
    @Value("${kakao.admin_key}")
    private String adminKey;

    @Value("${kakao.redirect_uris}")
    private List<String> redirectUris;

    public Map<String, String> loginOrSignup(String code, String currentUri) {

        log.info("입력된 currentUri: {}", currentUri);

        String selectedUri = redirectUris.stream()
                .filter(uri -> currentUri != null && (currentUri.contains(uri) || uri.contains("swagger-ui")))
                .findFirst()
                .orElse(redirectUris.get(0));

        log.info("최종 선택된 Redirect URI: {}", selectedUri);

        String kakaoAccessToken = getKakaoAccessToken(code, selectedUri);
        KakaoUserInfo userInfo = getKakaoUserInfo(kakaoAccessToken);

        User user = userRepository.findBySocialId(userInfo.getProviderId())
                .orElseGet(() -> userRepository.save(User.builder()
                        .socialId(userInfo.getProviderId())
                        .email(userInfo.getEmail())
                        .nickname(userInfo.getName())
                        .provider(userInfo.getProvider())
                        .build()));

        String accessToken = tokenProvider.createToken(user.getSocialId());
        String refreshToken = tokenProvider.createRefreshToken(user.getSocialId());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        return tokens;
    }

    private String getKakaoAccessToken(String code, String redirectUri) {
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

    // 탈퇴
    @Transactional
    public void withdraw(String socialId){
        unlinkKakao(socialId);

        User user = userRepository.findBySocialId(socialId)
                .orElseThrow(()-> new RuntimeException("해당 유저를 찾을 수 없습니다."));
        userRepository.delete(user);
    }

    private void unlinkKakao(String socialId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "KakaoAK " + adminKey);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("target_id_type", "user_id");
        params.add("target_id", socialId);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    "https://kapi.kakao.com/v1/user/unlink",
                    request,
                    String.class
            );
            log.info("카카오 연결 끊기 성공: {}", response.getBody());
        } catch (Exception e) {
            log.error("카카오 연결 끊기 실패: {}", e.getMessage());
            throw new RuntimeException("카카오 인증 서버와의 통신 중 오류가 발생했습니다.");
        }
    }
}
