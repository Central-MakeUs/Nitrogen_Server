package com.nitrogen.global.auth.security;

import com.nitrogen.global.apiPayload.code.status.ErrorStatus;
import com.nitrogen.global.apiPayload.exception.GeneralException;
import com.nitrogen.global.auth.service.UserDetailService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class TokenProvider {

    private final UserDetailService userDetailService;
    private final Key key;
    private final long expiration;
    private final long refreshExpiration;

    private final long registerExpiration = 1000 * 60 * 10;

    public TokenProvider(
            UserDetailService userDetailsService,
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expiration,
            @Value("${jwt.refresh-expiration-ms}") long refreshExpiration
    ) {
        this.userDetailService = userDetailsService;
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        this.expiration = expiration;
        this.refreshExpiration = refreshExpiration;
    }

    public String createToken(String socialId) {
        return createJwt(socialId, expiration, "ACCESS");
    }

    public String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        String socialId = getSocialIdFromToken(token);

        UserDetails userDetails = userDetailService.loadUserByUsername(socialId);

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }
    private String createJwt(String subject, long expiryTime, String type) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + expiryTime);
        return Jwts.builder()
                .setSubject(subject)
                .claim("type", type)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getSocialIdFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    public String createRefreshToken(String socialId) {
        return createJwt(socialId, refreshExpiration, "REFRESH");
    }

    public String getTokenType(String token) {
        return parseClaims(token).get("type", String.class);
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        } catch (JwtException e) {
            throw new GeneralException(ErrorStatus.INVALID_TOKEN);
        }
    }


    // apple
    public String createAppleRegisterToken(String appleSub, String email) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + registerExpiration);

        return Jwts.builder()
                .setSubject(appleSub)
                .claim("email", email)
                .claim("type", "REGISTER")
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // kakao
    public String createKakaoRegisterToken(String socialId, String email, String nickname) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + registerExpiration);

        return Jwts.builder()
                .setSubject(socialId)
                .claim("email", email)
                .claim("nickname", nickname)
                .claim("type", "REGISTER")
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * 임시 토큰 파싱 및 검증
     */
    public Claims parseRegisterToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            if (!"REGISTER".equals(claims.get("type"))) {
                throw new GeneralException(ErrorStatus.INVALID_REGISTER_TOKEN);
            }
            return claims;
        } catch (ExpiredJwtException e) {
            throw new GeneralException(ErrorStatus.REGISTER_TOKEN_EXPIRED);
        } catch (JwtException e) {
            throw new GeneralException(ErrorStatus.INVALID_TOKEN);
        }
    }

}