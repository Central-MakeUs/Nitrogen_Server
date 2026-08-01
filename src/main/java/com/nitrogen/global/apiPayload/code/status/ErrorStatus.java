package com.nitrogen.global.apiPayload.code.status;

import org.springframework.http.HttpStatus;

public enum ErrorStatus {
    // User
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "U001", "해당 유저를 찾을 수 없습니다."),
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "U002", "이미 존재하는 유저입니다."),
    ALREADY_REGISTERED_USER(HttpStatus.CONFLICT, "U003", "이미 일반 회원가입을 완료한 사용자입니다."),

    // Token
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "TOKEN401", "잘못된 토큰입니다."),
    INVALID_REGISTER_TOKEN(HttpStatus.UNAUTHORIZED, "TOKEN402", "회원가입 전용 임시 토큰이 아닙니다."),
    REGISTER_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "TOKEN403", "임시 토큰이 만료되었습니다. 다시 로그인해주세요."),

    // Expense
    EXPENSE_FORBIDDEN(HttpStatus.FORBIDDEN, "EXP403", "해당 지출 내역에 대한 권한이 없습니다."),
    EXPENSE_NOT_FOUND(HttpStatus.NOT_FOUND, "EXP404", "해당 지출 내역을 찾을 수 없습니다."),
    EXPENSE_INVALID_AMOUNT(HttpStatus.BAD_REQUEST, "EXP001", "지출기록은 0보다 커야합니다."),
    EXPENSE_USAGE_EMPTY(HttpStatus.BAD_REQUEST, "EXP002", "사용처 기록이 비어있습니다."),
    EXPENSE_FUTURE_DATE(HttpStatus.BAD_REQUEST, "EXP003", "미래 날짜로 소비 기록을 작성할 수 없습니다."),
    EXPENSE_REMIND_TOO_EARLY(HttpStatus.BAD_REQUEST, "EXP004", "소비 회고는 기록한 다음 날부터 가능합니다."),

    // Category
    CATEGORY_NOT_FOUND(HttpStatus.NOT_FOUND, "CAT404", "카테고리가 존재하지 않거나 접근 권한이 없습니다."),

    // Onboarding
    INVALID_ONBOARDING_TYPE(HttpStatus.BAD_REQUEST, "ONB001", "유효하지 않은 온보딩 유형입니다."),

    // Report
    MONTHLY_REPORT_NOT_OPENED(HttpStatus.BAD_REQUEST, "RPT001", "월간 분석 리포트가 아직 열리지 않았습니다."),

    // Apple Auth
    APPLE_AUTH_FAILED(HttpStatus.BAD_GATEWAY, "APPLE501", "애플 인증 서버 통신에 실패했습니다."),
    APPLE_TOKEN_DECODE_FAILED(HttpStatus.BAD_GATEWAY, "APPLE502", "애플 유저 정보 추출에 실패했습니다."),
    APPLE_NOTIFICATION_INVALID(HttpStatus.BAD_REQUEST, "APPLE400", "신뢰할 수 없는 애플 알림입니다."),

    // Server
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "S001", "서버 내부 오류가 발생했습니다."),

    // Global / Handler
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "4000", "유효성 검증에 실패했습니다."),
    ILLEGAL_ARGUMENT(HttpStatus.BAD_REQUEST, "4001", "잘못된 요청입니다."),
    MESSAGE_NOT_READABLE(HttpStatus.BAD_REQUEST, "4002", "요청 데이터 형식이 잘못되었거나 누락된 필드가 있습니다."),
    UNKNOWN_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "5999", "알 수 없는 서버 오류가 발생했습니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;

    ErrorStatus(HttpStatus httpStatus, String code, String message) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.message = message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
