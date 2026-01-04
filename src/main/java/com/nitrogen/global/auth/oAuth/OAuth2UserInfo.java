package com.nitrogen.global.auth.oAuth;

public interface OAuth2UserInfo {
    String getProviderId();
    String getProvider();
    String getName();
    String getEmail();
}
