package com.nitrogen.domain.expense.entity.enums;

public enum EmotionType {
    ENTRANCED("홀린듯이"),
    STRESS("스트레스"),
    FOR_SELF("나를 위해서"),
    SURVIVAL("살기 위해"),
    INVESTMENT("투자"),
    HABIT("습관처럼");

    private final String emotion_description;

    EmotionType(String emotion_description) {
        this.emotion_description = emotion_description;
    }
}
