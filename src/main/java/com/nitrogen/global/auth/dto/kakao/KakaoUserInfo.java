package com.nitrogen.global.auth.dto.kakao;

import com.nitrogen.global.auth.oAuth.OAuth2UserInfo;
import lombok.AllArgsConstructor;

import java.util.Map;
@AllArgsConstructor
public class KakaoUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    @Override
    public String getProviderId() {
        return attributes != null && attributes.get("id") != null
                ? String.valueOf(attributes.get("id"))
                : "unknown";
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getName() {
        try {
            return (String) ((Map) attributes.get("properties")).get("nickname");
        } catch (Exception e) {
            return "UnknownUser";
        }
    }

    public String getEmail(){
        try {
            return (String)((Map) attributes.get("kakao_account")).get("email");
        } catch (Exception e) {
            return null;
        }
    }
}
