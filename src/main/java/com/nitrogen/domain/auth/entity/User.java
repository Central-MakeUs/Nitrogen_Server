package com.nitrogen.domain.auth.entity;

import jakarta.persistence.Entity;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Entity
@NoArgsConstructor
@Getter
@Builder
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue
    @Column(unique = true, nullable = false, name = "USER_ID")
    private long userId;

    @Column(unique = true, nullable = false, name = "EMAIL")
    private String email;

    @Column(name = "PASSWORD")
    private String password;

    @Column(name = "NICKNAME")
    private String nickname;

    @Column(name = "PROFILE_URL")
    private String profileUrl;

    @Column(name = "REFRESH_TOKEN", length = 1000)
    private String refreshToken;

    @Builder.Default
    @Column(name = "USER_ROLE")
    private String userRole = "ROLE_USER";

    @Enumerated(EnumType.STRING)
    @Column(name = "SOCIAL_TYPE")
    private SocialType socialType;

    @Column(name = "socialId")
    private String socialId; // 로그인한 소셜 타입의 식별자 값 (일반 로그인인 경우 null)

    // refreshToken 재설정
    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    // 비밀번호 암호화
    public void passwordEncode(PasswordEncoder passwordEncoder){
        this.password = passwordEncoder.encode(this.password);
    }
}