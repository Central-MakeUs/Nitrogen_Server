package com.nitrogen.global.auth.security;

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
        return createJwt(socialId, expiration);
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
    private String createJwt(String subject, long expiryTime) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + expiryTime);
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getSocialIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    public String createRefreshToken(String username) {
        return createJwt(username, refreshExpiration);
    }

}