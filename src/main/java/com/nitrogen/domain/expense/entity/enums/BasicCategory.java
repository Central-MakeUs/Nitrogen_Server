package com.nitrogen.domain.expense.entity.enums;

public enum BasicCategory {
    FOOD("식비"),
    CAFE("카페"),
    SUBSCRIPTION("구독"),
    EDUCATION("교육"),
    BEAUTY("미용"),
    ENTERTAINMENT("유흥"),
    SHOPPING("쇼핑"),
    CUSTOM("커스텀");

    private final String defaultName;
    BasicCategory(String defaultName){
        this.defaultName = defaultName;

    }
    public String getDefaultName(){
        return  defaultName;
    }

}
