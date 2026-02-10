package com.nitrogen.domain.expense.entity.enums;

public enum CategoryIconType {
    COOK,    // 식비
    COFFEE,  // 카페
    CREDIT,  // 구독
    BOOK,    // 교육
    BEAUTY,  // 미용
    BEER,    // 유흥
    SHOPPING,// 쇼핑
    CAMERA,  // 취미
    CUP;     // 라이프

    @com.fasterxml.jackson.annotation.JsonValue
    public String getValue() {
        return name().toLowerCase();
    }
}
