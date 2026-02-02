package com.nitrogen.domain.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

public class UserResponseDTO {

    @Getter
    @Builder
    @AllArgsConstructor
    public static class TokenReissueResultDTO {
        String accessToken;
    }
}
