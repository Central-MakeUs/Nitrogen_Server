package com.nitrogen.domain.user.dto;

import lombok.*;

public class UserResponseDTO {
    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenReissueResultDTO {
        String accessToken;
        String refreshToken;
    }
}
