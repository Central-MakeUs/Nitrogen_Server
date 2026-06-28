package com.nitrogen.domain.user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nitrogen.domain.alert.entity.Alert;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.user.entity.enums.UserStatus;
import com.nitrogen.global.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter @Setter @Builder @AllArgsConstructor
public class User extends BaseEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(unique = true)
    private String email;

    private String provider; // "kakao" 또는 "apple" 저장용 필드

    private String nickname;
    private String profileUrl;

    @Column(length = 1000)
    private String refreshToken;

    @Builder.Default
    private String userRole = "ROLE_USER";

    @Column(unique = true) // 소셜 로그인의 핵심
    private String socialId;

    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @Column(unique = true)
    private String appleSub; // 애플 고유 식별자

    /**
     * 애플 OAuth 서버가 발급한 refresh token.
     * 회원 탈퇴 시 애플 연동 해제(https://appleid.apple.com/auth/revoke)에 반드시 필요
     * 우리 서비스의 JWT refresh token(refreshToken 필드)과는 별개
     * 카카오 유저는 null처리
     */
    @Column(length = 1000)
    private String appleRefreshToken;

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Category> categories = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Expense> expenses = new ArrayList<>();

    @Column
    private String fcmToken;

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Alert> alerts = new ArrayList<>();

    // 0226
    @Builder.Default
    private boolean isHomeOnboarding = true;
    @Builder.Default
    private boolean isCategoryOnboarding = true;
    @Builder.Default
    private boolean isRemindOnboarding = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean isAlarmOn = false;

    public void updateAlarmSetting(boolean status) {
        this.isAlarmOn = status;
    }

}