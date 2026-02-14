package com.nitrogen.global.auth.converter;

import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.auth.dto.apple.AppleUserResponseDTO;

public class AppleUserConverter {
    public static AppleUserResponseDTO toLoginResultDTO(User user, String accessToken, boolean isNewUser) {
        return AppleUserResponseDTO.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .accessToken(accessToken)
                .refreshToken(user.getRefreshToken())
                .appleSub(user.getAppleSub())
                .isNewUser(isNewUser)
                .build();
    }
}
