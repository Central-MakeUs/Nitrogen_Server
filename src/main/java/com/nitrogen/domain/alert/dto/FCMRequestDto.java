package com.nitrogen.domain.alert.dto;

public record FCMRequestDto(
        String targetUserId,
        String title,
        String body,
        String redirectUrl // 알림 클릭 시 이동할 주소 추가(필수가 아니므로 null 가능)
) {
}
