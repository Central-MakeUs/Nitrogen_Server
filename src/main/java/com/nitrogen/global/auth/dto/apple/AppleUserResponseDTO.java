package com.nitrogen.global.auth.dto.apple;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AppleUserResponseDTO {
    private Long userId;
    private String email;
    private String nickname;
    private String accessToken;
    private String refreshToken;
    private String appleSub;
    private boolean isNewUser;
}
