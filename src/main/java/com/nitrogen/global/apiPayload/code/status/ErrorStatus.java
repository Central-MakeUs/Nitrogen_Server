package com.nitrogen.global.apiPayload.code.status;

import org.springframework.http.HttpStatus;

public enum ErrorStatus {
    USER_NOT_FOUND("U001","해당 유저를 찾을 수 없습니다."),
    USER_ALREADY_EXISTS("U002", "이미 존재하는 유저입니다."),
    INTERNAL_ERROR("S001", "서버 내부 오류가 발생했습니다."),
    ALREADY_REGISTERED_USER("USER409", "이미 일반 회원가입을 완료한 사용자입니다."),

    INVALID_TOKEN("TOKEN4003", "잘못된 토큰입니다."),
    EXPENSE_FORBIDDEN("EXP403", "해당 지출 내역에 대한 권한이 없습니다."),
    EXPENSE_NOT_FOUND("EXP404", "해당 지출 내역을 찾을 수 없습니다."),
    INVALID_ONBOARDING_TYPE("EXP405", "유효하지 않은 온보딩 유형입니다.");


    private final String code;
    private final String message;

    ErrorStatus(String code, String message){
        this.code = code;
        this.message = message;
    }

    public String getCode(){
        return code;
    }
    public String getMessage(){
        return message;
    }


}
