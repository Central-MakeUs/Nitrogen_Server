package com.nitrogen.global.auth.security;

import com.nitrogen.global.auth.service.UserDetailService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class TokenProvider {

    private final UserDetailService userDetailsService;
    private final Key key;
    private final long expiration;
    private final long refreshExpiration;

    public TokenProvider(
            UserDetailService userDetailsService,
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expiration,
            @Value("${jwt.refresh-expiration-ms}") long refreshExpiration
    ) {
        this.userDetailsService = userDetailsService;
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        this.expiration = expiration;
        this.refreshExpiration = refreshExpiration;
    }

    public String createToken(String socialId) {
        return createJwt(socialId, expiration);
    }

    public String createRefreshToken(String socialId) {
        return createJwt(socialId, refreshExpiration);
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
}