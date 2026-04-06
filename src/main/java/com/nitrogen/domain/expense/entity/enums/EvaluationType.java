package com.nitrogen.domain.expense.entity.enums;

import lombok.Getter;

@Getter
public enum EvaluationType {
    VERY_SATISFIED("정말 만족했어요", 5.0),
    SATISFIED("대체로 만족해요", 4.0),
    NORMAL("그냥 그랬어요", 3.0),
    DISAPPOINTED("조금 아쉬워요", 2.0),
    VERY_DISAPPOINTED("별로였어요", 1.0);

    private final String evaluation_description;
    private final double score;
    EvaluationType(String evaluation_description, double score){
        this.evaluation_description = evaluation_description;
        this.score = score;
    }
}
