package com.nitrogen.domain.expense.entity.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum EmotionType {
    TYPE_A("기분 전환"),
    TYPE_B("그냥 저냥"),
    TYPE_C("필수템"),
    TYPE_D("홀린 듯이"),
    TYPE_E("살기 위해");

    private final String emotion_description;

    EmotionType(String emotion_description) {
        this.emotion_description = emotion_description;
    }

    @JsonValue
    public String getEmotion_description() {
        return emotion_description;
    }
}
