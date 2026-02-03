package com.nitrogen.global.auth.dto.apple;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter @Setter
public class ApplePublicKeyResponse {
    private List<AppleKey> keys;

    @Getter
    @Setter
    public static class AppleKey {
        private String kty;
        private String kid;
        private String use;
        private String alg;
        private String n;
        private String e;
    }
}
