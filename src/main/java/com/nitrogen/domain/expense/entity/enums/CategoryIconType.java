package com.nitrogen.domain.expense.entity.enums;

public enum CategoryIconType {
    COIN, PERCENT, SHOPPING, PLUS;

    @com.fasterxml.jackson.annotation.JsonValue
    public String getValue() {
        return name().toLowerCase();
    }
}
