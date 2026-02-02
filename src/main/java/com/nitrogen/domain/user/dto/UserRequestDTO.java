package com.nitrogen.domain.user.dto;

import lombok.Getter;
import lombok.Setter;

public class UserRequestDTO {
    @Getter
    @Setter
    public static class TokenReissueDTO {
        private String refreshToken;
    }
}
