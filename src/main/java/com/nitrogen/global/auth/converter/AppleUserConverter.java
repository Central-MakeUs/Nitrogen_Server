package com.nitrogen.global.auth.converter;

import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.auth.dto.apple.AppleUserResponseDTO;

public class AppleUserConverter {
    public static AppleUserResponseDTO toLoginResultDTO(User user, String accessToken, String refreshToken, boolean isNewUser, boolean hasExpense) {
        return AppleUserResponseDTO.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .appleSub(user.getAppleSub())
                .newUser(isNewUser)
//                .termsAgreed(user.isTermsAgreed())
                .hasExpense(hasExpense)
                .build();
    }
}
