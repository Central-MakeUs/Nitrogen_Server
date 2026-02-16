package com.nitrogen.global.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private UserInfo user;

    @Getter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class UserInfo {
        private Long userId;
        private String nickname;
//        private Integer age;
//        private String gender;
//        private String region;
        private String type;     // kakao, apple

        @JsonProperty("isNewUser")
        private boolean isNewUser;
        @JsonProperty("isTermsAgreed")
        private boolean isTermsAgreed;
        @JsonProperty("hasExpense")
        private boolean hasExpense;
    }
}
