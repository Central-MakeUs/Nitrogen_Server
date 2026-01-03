package com.mathfusion.domain.user.security;

import com.mathfusion.domain.user.exception.JwtErrorCode;
import com.mathfusion.domain.user.exception.JwtException;
import com.mathfusion.domain.user.service.UserDetailService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
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

    public String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new JwtException(JwtErrorCode.EXPIRED_TOKEN);
        } catch (Exception e) {
            throw new JwtException(JwtErrorCode.INVALID_TOKEN);
        }
    }

    public Authentication getAuthentication(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            String username = claims.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
        } catch (Exception e) {
            throw new JwtException(JwtErrorCode.INVALID_TOKEN);
        }
    }

    public String createToken(String username) {
        return createJwt(username, expiration);
    }

    public String createRefreshToken(String username) {
        return createJwt(username, refreshExpiration);
    }

    private String createJwt(String username, long expiryTime) {
        try {
            Date now = new Date();
            Date validity = new Date(now.getTime() + expiryTime);
            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(now)
                    .setExpiration(validity)
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
        } catch (Exception e) {
            throw new JwtException(JwtErrorCode.INVALID_TOKEN);
        }
    }
}