package com.nitrogen.domain.alert.dto;

public record FCMRequestDto (
        Long targetUserId,
        String title,
        String body
) {
}
