package com.nitrogen.global.auth.service.kakao_apple;

import com.nitrogen.domain.expense.service.category.CategoryService;
import com.nitrogen.domain.user.dto.UserResponseDTO;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.entity.enums.UserStatus;
import com.nitrogen.domain.user.repository.UserRepository;
import com.nitrogen.global.apiPayload.code.status.ErrorStatus;
import com.nitrogen.global.apiPayload.exception.UserHandler;
import com.nitrogen.global.auth.dto.apple.ApplePublicKeyResponse;
import com.nitrogen.global.auth.dto.apple.AppleTokenResponseDTO;
import com.nitrogen.global.auth.dto.kakao.KakaoUserInfo;
import com.nitrogen.global.auth.security.TokenProvider;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class OauthService {
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final CategoryService categoryService;
    private final RestTemplate restTemplate = new RestTemplate();

    // kakao

    @Value("${kakao.client_id}")
    private String clientId;

    @Value("${kakao.client_secret}")
    private String clientSecret;

    @Value("${kakao.admin_key}")
    private String adminKey;

    @Value("${kakao.redirect_uris}")
    private List<String> redirectUris;

    // apple

    @Value("${social-login.provider.apple.client-id}")
    private String appleClientId;

    @Value("${social-login.provider.apple.team-id}")
    private String appleTeamId;

    @Value("${social-login.provider.apple.key-id}")
    private String appleKeyId;

    @Value("${social-login.provider.apple.private-key}")
    private String applePrivateKey;

    @Value("${social-login.provider.apple.redirect-uri}")
    private String appleRedirectUri;

    // kakao
    public Map<String, Object> loginOrSignup(String code, String currentUri) {

        final String requestUri = (currentUri != null) ? currentUri.split("\\?")[0] : "";

        boolean isValidUri = redirectUris.stream()
                .anyMatch(uri -> requestUri.contains(uri) || uri.contains(requestUri));

        String selectedUri = isValidUri ? requestUri : redirectUris.get(0);

        log.info("카카오 인증에 사용될 Redirect URI: {}", selectedUri);

        String kakaoAccessToken = getKakaoAccessToken(code, selectedUri);
        KakaoUserInfo userInfo = getKakaoUserInfo(kakaoAccessToken);

        User user = userRepository.findBySocialId(userInfo.getProviderId())
                .orElseGet(() -> userRepository.save(User.builder()
                        .socialId(userInfo.getProviderId())
                        .email(userInfo.getEmail())
                        .nickname(userInfo.getName())
                        .provider(userInfo.getProvider())
                        .build()));

        categoryService.initUserCategories(user);

        String accessToken = tokenProvider.createToken(user.getSocialId());
        String refreshToken = tokenProvider.createRefreshToken(user.getSocialId());

        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        Map<String, Object> result = new HashMap<>();
        result.put("accessToken", accessToken);
        result.put("refreshToken", refreshToken);
        result.put("user", user);

        return result;
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
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    "https://kauth.kakao.com/oauth/token",
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<>() {}
            );

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
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    "https://kapi.kakao.com/v2/user/me",
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<>() {}
            );
            return new KakaoUserInfo(response.getBody());
        } catch (Exception e) {
            log.error("카카오 사용자 정보 조회 실패: {}", e.getMessage());
            throw new RuntimeException("카카오 정보 조회 실패");
        }
    }
    @Transactional
    public void withdraw(String socialId){
        User user = userRepository.findBySocialId(socialId)
                .orElseThrow(() -> new RuntimeException("해당 유저를 찾을 수 없습니다."));

        unlinkKakao(socialId);

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
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            if (!e.getResponseBodyAsString().contains("-101")) {
                log.error("카카오 unlink 실패: {}", e.getResponseBodyAsString());
            }
        } catch (Exception e) {
            log.error("카카오 통신 중 알 수 없는 오류 발생: {}", e.getMessage());
        }
    }
    @Transactional
    public UserResponseDTO.TokenReissueResultDTO reissueToken (String refreshToken){

        if (!tokenProvider.validateToken(refreshToken)) {
            throw new UserHandler(ErrorStatus.INVALID_TOKEN);
        }

        Authentication authentication = tokenProvider.getAuthentication(refreshToken);
        String socialId = authentication.getName();

        User user = userRepository.findBySocialId(socialId)
                .orElseThrow(() -> new UserHandler(ErrorStatus.USER_NOT_FOUND));

        if (!refreshToken.equals(user.getRefreshToken())) {
            throw new UserHandler(ErrorStatus.INVALID_TOKEN);
        }

        String newAccessToken = tokenProvider.createToken(socialId);

        return UserResponseDTO.TokenReissueResultDTO.builder()
                .accessToken(newAccessToken)
                .build();
    }

    // apple
    public Map<String, Object> appleLoginOrSignup(String code){
        AppleTokenResponseDTO tokenResponse = getAppleToken(code);
        String appleSub = decodeIdToken(tokenResponse.getIdToken());

        User user = userRepository.findByAppleSub(appleSub)
                .orElseGet(() -> userRepository.save(User.builder()
                        .appleSub(appleSub)
                        .provider("apple")
                        .status(UserStatus.ACTIVE)
                        .build()));

        categoryService.initUserCategories(user);

        String accessToken = tokenProvider.createToken(user.getSocialId());
        String refreshToken = tokenProvider.createRefreshToken(user.getSocialId());

        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        Map<String, Object> result = new HashMap<>();
        result.put("accessToken", accessToken);
        result.put("refreshToken", refreshToken);
        result.put("user", user);

        return result;
    }

    private AppleTokenResponseDTO getAppleToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", appleClientId);
        params.add("client_secret", makeClientSecretToken());
        params.add("code", code);
        params.add("redirect_uri", appleRedirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<AppleTokenResponseDTO> response = restTemplate.postForEntity(
                    "https://appleid.apple.com/auth/token", request, AppleTokenResponseDTO.class);
            return response.getBody();
        } catch (Exception e) {
            log.error("애플 토큰 발급 실패: {}", e.getMessage());
            throw new RuntimeException("애플 인증 서버 통신 실패");
        }
    }
    private String decodeIdToken(String idToken) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                        @Override
                        public Key resolveSigningKey(JwsHeader header, Claims claims) {
                            return getApplePublicKey(header.getKeyId());
                        }
                    })
                    .build()
                    .parseClaimsJws(idToken);

            return jws.getBody().getSubject();
        } catch (Exception e) {
            log.error("ID 토큰 디코딩 실패: {}", e.getMessage());
            throw new RuntimeException("애플 유저 정보 추출 실패");
        }
    }
    private String makeClientSecretToken() {
        Date now = new Date();

        Date expiration = new Date(now.getTime() + 1000 * 60 * 5);

        return Jwts.builder()
                .setHeaderParam("kid", appleKeyId)
                .setHeaderParam("alg", "ES256")
                .setIssuer(appleTeamId)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .setAudience("https://appleid.apple.com")
                .setSubject(appleClientId)
                .signWith(getPrivateKey(), SignatureAlgorithm.ES256)
                .compact();
    }
    private PrivateKey getPrivateKey() {
        try {
            String privateKeyContent = applePrivateKey
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            log.error("애플 개인키 생성 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("애플 인증 설정 오류");
        }
    }

    // server to server
    public void handleAppleServerNotification(String payload) {
        try{
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                        @Override
                        public Key resolveSigningKey(JwsHeader header, Claims claims) {
                            return getApplePublicKey(header.getKeyId());
                        }
                    })
                    .build()
                    .parseClaimsJws(payload);

            Claims body = jws.getBody();
            String notificationType = body.get("notificationType", String.class);
            if (!"CONSENT_REVOKED".equals(notificationType)) {
                return; // 관심 없는 알림
            }

            Object dataObj = body.get("data");
            if (!(dataObj instanceof Map<?, ?> data)) {
                log.warn("data 형식 오류");
                return;
            }

            Object signedTxObj = data.get("signedTransactionInfo");
            if (!(signedTxObj instanceof String signedTransactionInfo)) {
                log.warn("signedTransactionInfo 형식 오류");
                return;
            }

            Jws<Claims> txJws = Jwts.parserBuilder()
                    .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                        @Override
                        public Key resolveSigningKey(JwsHeader header, Claims claims) {
                            return getApplePublicKey(header.getKeyId());
                        }
                    })
                    .build()
                    .parseClaimsJws(signedTransactionInfo);

            Claims txClaims = txJws.getBody();
            String appleSub = txClaims.getSubject();

            log.info("CONSENT_REVOKED 유저 sub={}", appleSub);
            handleUserRevoke(appleSub);
        }catch (Exception e) {
            log.error("애플 서명 검증 실패: {}", e.getMessage());
            throw new RuntimeException("신뢰할 수 없는 애플 알림입니다.");
        }
    }

    /**
     * 애플의 공개키 목록조회 -> 특정 kid에 해당하는 PublicKey를 생성
     */
    private PublicKey getApplePublicKey(String kid) {
        try {
            ApplePublicKeyResponse response = restTemplate.getForObject(
                    "https://appleid.apple.com/auth/keys",
                    ApplePublicKeyResponse.class
            );

            if (response == null || response.getKeys() == null) {
                throw new RuntimeException("애플 공개키 목록을 가져오는데 실패했습니다.");
            }

            ApplePublicKeyResponse.AppleKey appleKey = response.getKeys().stream()
                    .filter(key -> key.getKid().equals(kid))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("일치하는 애플 공개키가 없습니다."));

            byte[] xBytes = Base64.getUrlDecoder().decode(appleKey.getN());
            byte[] yBytes = Base64.getUrlDecoder().decode(appleKey.getE());

            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

            // EC Point
            ECPoint ecPoint = new ECPoint(
                    new BigInteger(1, xBytes),
                    new BigInteger(1, yBytes)
            );

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(publicKeySpec);

        } catch (Exception e) {
            log.error("애플 공개키 생성 중 오류: {}", e.getMessage());
            throw new RuntimeException("애플 서버 인증에 실패했습니다.");
        }
    }

    /**
     *
     * 실제 유저 처리 로직 호출
     */
    private void handleUserRevoke(String appleSub) {
        userRepository.findByAppleSub(appleSub).ifPresent(user -> {
            log.info("유저 연결 해제 처리: {}", user.getEmail());

            userRepository.delete(user);
        });
    }

    // 공통 로그아웃
    @Transactional
    public void logout(String socialId) {
        User user = userRepository.findBySocialId(socialId)
                .orElseGet(() -> userRepository.findByAppleSub(socialId)
                        .orElseThrow(() -> new UserHandler(ErrorStatus.USER_NOT_FOUND)));
        user.setRefreshToken(null);
        userRepository.save(user);

        log.info("유저 로그아웃 성공 (ID: {})", socialId);
    }
}
