package com.nitrogen.global.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private UserInfo user;

    @Getter
    @Builder
    public static class UserInfo {
        private Long userId;
        private String nickname;
//        private Integer age;
//        private String gender;
//        private String region;
        private String type;     // kakao, apple

        private boolean isNewUser;
        private boolean isTermsAgreed;
        private boolean hasExpense;
    }
}
