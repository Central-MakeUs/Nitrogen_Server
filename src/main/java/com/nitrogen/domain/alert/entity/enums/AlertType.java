package com.nitrogen.domain.alert.entity.enums;

public enum AlertType {
    RETROSPECT,       // 소비 회고 알림 (전날 만족도 평가 미완료 시 - 사진의 '돌아보기 알림')
    WEEKLY_REPORT,    // 주차 분석 리포트 알림 (인앱 알림)
    SERVICE_NOTICE,   // 서비스 공지사항 (후순위지만 기반은 마련)
}
