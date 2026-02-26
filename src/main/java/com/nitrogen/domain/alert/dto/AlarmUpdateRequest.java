package com.nitrogen.domain.alert.dto;

public record AlarmUpdateRequest(
        // 알람 스위치 UI에서 보낼 요청 박스
        boolean isAlarmOn
) {}
