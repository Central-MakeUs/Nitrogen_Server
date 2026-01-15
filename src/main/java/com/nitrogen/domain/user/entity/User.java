package com.nitrogen.domain.user.entity;

import com.nitrogen.domain.user.entity.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter @Builder @AllArgsConstructor
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(unique = true, nullable = false)
    private String email;

    private String provider; // "kakao" 또는 "apple" 저장용 필드

    private String nickname;
    private String profileUrl;

    @Column(length = 1000)
    private String refreshToken;

    @Builder.Default
    private String userRole = "ROLE_USER";

    @Column(unique = true, nullable = false) // 소셜 로그인의 핵심
    private String socialId;

    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @Column(unique = true)
    private String appleSub; // 애플 고유 식별자


}