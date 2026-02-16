package com.nitrogen.global.auth.service.kakao_apple;

import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.expense.service.category.CategoryService;
import com.nitrogen.domain.user.dto.UserResponseDTO;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.entity.enums.UserStatus;
import com.nitrogen.domain.user.repository.UserRepository;
import com.nitrogen.global.apiPayload.code.status.ErrorStatus;
import com.nitrogen.global.apiPayload.exception.UserHandler;
import com.nitrogen.global.auth.converter.AppleUserConverter;
import com.nitrogen.global.auth.dto.apple.ApplePublicKeyResponse;
import com.nitrogen.global.auth.dto.apple.AppleTokenResponseDTO;
import com.nitrogen.global.auth.dto.apple.AppleUserResponseDTO;
import com.nitrogen.global.auth.dto.kakao.KakaoUserInfo;
import com.nitrogen.global.auth.security.TokenProvider;
import io.jsonwebtoken.*;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class OauthService {
    private final UserRepository userRepository;
    private final ExpenseRepository expenseRepository;
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

    @Value("${social-login.provider.apple.app-client-id}")
    private String appleAppClientId;

    @Value("${social-login.provider.apple.service-client-id}")
    private String appleServiceClientId;

    @Value("${social-login.provider.apple.team-id}")
    private String appleTeamId;

    @Value("${social-login.provider.apple.key-id}")
    private String appleKeyId;

    @Value("${social-login.provider.apple.private-key}")
    private String applePrivateKey;

//    @Value("${social-login.provider.apple.redirect-uri}")
//    private String appleRedirectUri;

    // kakao
    public Map<String, Object> loginOrSignup(Map<String, Object> body) {
        String kakaoAccessToken = (String) body.get("accessToken");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + kakaoAccessToken);
        Map<String, Object> kakaoAttributes = restTemplate.exchange(
                "https://kapi.kakao.com/v2/user/me", HttpMethod.GET, new HttpEntity<>(headers), Map.class
        ).getBody();

        KakaoUserInfo userInfo = new KakaoUserInfo(kakaoAttributes);

        Optional<User> optionalUser = userRepository.findBySocialId(userInfo.getProviderId());
        boolean isNewUser = optionalUser.isEmpty();

        User user = optionalUser.orElseGet(() -> {
            User newUser = User.builder()
                    .socialId(userInfo.getProviderId())
                    .email(userInfo.getEmail())
                    .nickname(userInfo.getName())
                    .provider(userInfo.getProvider())
                    .status(UserStatus.ACTIVE)
                    .isTermsAgreed(false)
                    .hasExpense(false)
                    .build();

            User savedUser = userRepository.save(newUser);
            categoryService.initUserCategories(savedUser);
            return savedUser;
        });

        boolean hasExpense = expenseRepository.existsByUserUserId(user.getUserId());
        user.setHasExpense(hasExpense);

        String accessToken = tokenProvider.createToken(user.getSocialId());
        String refreshToken = tokenProvider.createRefreshToken(user.getSocialId());
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        Map<String, Object> result = new HashMap<>();
        result.put("accessToken", accessToken);
        result.put("refreshToken", refreshToken);
        result.put("user", user);
        result.put("isNewUser", isNewUser);
        result.put("isTermsAgreed", user.isTermsAgreed());
        result.put("hasExpense", hasExpense);

        return result;
    }

    // apple kakao 공통 로그아웃
    @Transactional
    public void withdraw(Long userId) { // String identifier 대신 Long userId를 받음
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("해당 유저를 찾을 수 없습니다."));

        if ("kakao".equals(user.getProvider())) {
            unlinkKakao(user.getSocialId());
        } else if ("apple".equals(user.getProvider())) {
            unlinkApple(user.getRefreshToken());
        }

        userRepository.delete(user);
    }

    private void unlinkApple(String appleRefreshToken) {
        if (appleRefreshToken == null) return;

        String clientId = appleAppClientId;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientId);
        params.add("client_secret", makeClientSecretToken(clientId));
        params.add("token", appleRefreshToken);
        params.add("token_type_hint", "refresh_token");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            restTemplate.postForEntity("https://appleid.apple.com/auth/revoke", request, String.class);
        } catch (Exception e) {
            log.error("Apple unlink failed: {}", e.getMessage());
        }
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
    public UserResponseDTO.TokenReissueResultDTO reissueToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new UserHandler(ErrorStatus.INVALID_TOKEN);
        }

        String identifier = tokenProvider.getSocialIdFromToken(refreshToken);

        User user = userRepository.findBySocialId(identifier)
                .or(() -> userRepository.findByAppleSub(identifier))
                .orElseThrow(() -> new UserHandler(ErrorStatus.USER_NOT_FOUND));

        String dbRefreshToken = user.getRefreshToken();
        if (dbRefreshToken == null || !dbRefreshToken.equals(refreshToken)) {
            throw new UserHandler(ErrorStatus.INVALID_TOKEN);
        }

        String newAccessToken = tokenProvider.createToken(identifier);
        String newRefreshToken = tokenProvider.createRefreshToken(identifier);

        user.updateRefreshToken(newRefreshToken);
        userRepository.save(user);

        return UserResponseDTO.TokenReissueResultDTO.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }

//------------------------------------------------------------------------------------------------------------------------

    // apple
    public AppleUserResponseDTO appleLoginOrSignup(String code, String platform){

        String targetClientId = "ios".equalsIgnoreCase(platform) ? appleAppClientId : appleServiceClientId;
        AppleTokenResponseDTO tokenResponse = getAppleToken(code, targetClientId);

        Map<String, String> appleInfo = decodeIdToken(tokenResponse.getIdToken());
        String appleSub = appleInfo.get("sub");
        String emailFromApple = appleInfo.get("email");
        log.info("애플 유저 식별자 추출 성공: {}", appleSub);

        Optional<User> optionalUser = userRepository.findByAppleSub(appleSub);
        boolean isNewUser = optionalUser.isEmpty();

        User user = optionalUser.orElseGet(() -> {
            User newUser = userRepository.save(User.builder()
                    .appleSub(appleSub)
                    .email(emailFromApple)
                    .provider("apple")
                    .status(UserStatus.ACTIVE)
                    .isTermsAgreed(false) // 애플은 나중에 API로 동의 받을 거니까 false
                    .hasExpense(false)
                    .build());
            categoryService.initUserCategories(newUser);
            return newUser;
        });

        boolean hasExpense = expenseRepository.existsByUserUserId(user.getUserId());
        user.setHasExpense(hasExpense);

        String tokenKey = user.getSocialId() != null ? user.getSocialId() : appleSub;
        String accessToken = tokenProvider.createToken(tokenKey);
        String refreshToken = tokenProvider.createRefreshToken(tokenKey);

        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return AppleUserConverter.toLoginResultDTO(user, accessToken, refreshToken, isNewUser, hasExpense);
    }
    private AppleTokenResponseDTO getAppleToken(String code, String clientId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("client_secret", makeClientSecretToken(clientId));
        params.add("code", code);

        log.info("애플 서버로 쏘는 client_id: {}", clientId);

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
    private Map<String, String> decodeIdToken(String idToken) {
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

            Claims body = jws.getBody();
            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("sub", body.getSubject());
            userInfo.put("email", body.get("email", String.class)); // 이메일 추출! (없으면 null)

            return userInfo;
        } catch (Exception e) {
            log.error("ID 토큰 디코딩 실패: {}", e.getMessage());
            throw new RuntimeException("애플 유저 정보 추출 실패");
        }
    }
    private String makeClientSecretToken(String clientId) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + 1000 * 60 * 5);

        return Jwts.builder()
                .setHeaderParam("kid", appleKeyId)
                .setHeaderParam("alg", "ES256")
                .setIssuer(appleTeamId)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .setAudience("https://appleid.apple.com")
                .setSubject(clientId)
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

            // RSA vs EC 분기
            if ("RSA".equals(appleKey.getKty())) {
                return generateRSAPublicKey(appleKey);
            } else if ("EC".equals(appleKey.getKty())) {
                return generateECPublicKey(appleKey);
            } else {
                throw new RuntimeException("지원하지 않는 키 타입: " + appleKey.getKty());
            }

        } catch (Exception e) {
            log.error("애플 공개키 생성 중 오류: {}", e.getMessage());
            throw new RuntimeException("애플 서버 인증에 실패했습니다.");
        }
    }

    private PublicKey generateRSAPublicKey(ApplePublicKeyResponse.AppleKey appleKey) throws Exception {
        byte[] nBytes = Base64.getUrlDecoder().decode(appleKey.getN());
        byte[] eBytes = Base64.getUrlDecoder().decode(appleKey.getE());

        BigInteger modulus = new BigInteger(1, nBytes);
        BigInteger exponent = new BigInteger(1, eBytes);

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicKeySpec);
    }

    private PublicKey generateECPublicKey(ApplePublicKeyResponse.AppleKey appleKey) throws Exception {
        byte[] xBytes = Base64.getUrlDecoder().decode(appleKey.getX());
        byte[] yBytes = Base64.getUrlDecoder().decode(appleKey.getY());

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPoint ecPoint = new ECPoint(
                new BigInteger(1, xBytes),
                new BigInteger(1, yBytes)
        );

        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(publicKeySpec);
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

    // 약관동의(동의하는 메서드이므로 true)
    @Transactional
    public void agreeUserTerms(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserHandler(ErrorStatus.USER_NOT_FOUND));
        user.agreeTerms();
    }
}
