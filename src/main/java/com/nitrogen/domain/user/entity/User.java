package com.nitrogen.domain.user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.user.entity.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter @Setter @Builder @AllArgsConstructor
public class User {
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

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Category> categories = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Expense> expenses = new ArrayList<>();


}