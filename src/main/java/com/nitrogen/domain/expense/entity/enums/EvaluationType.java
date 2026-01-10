package com.nitrogen.domain.expense.entity.enums;

public enum EvaluationType {
    VERY_SATISFIED("정말 만족했어요"),
    SATISFIED("대체로 만족해요"),
    NORMAL("그냥 그랬어요"),
    DISAPPOINTED("조금 아쉬워요"),
    VERY_DISAPPOINTED("별로였어요");

    private final String evaluation_description;
    EvaluationType(String evaluation_description){ this.evaluation_description = evaluation_description;}
}
