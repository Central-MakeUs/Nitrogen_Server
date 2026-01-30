package com.nitrogen.domain.expense.entity.enums;

public enum SatisfactionLevel {
    BAD("별로였어요.", 1.0, 2.0),
    DISAPPOINTED("조금 아쉬워요.", 2.0, 3.0),
    NORMAL("그냥 그랬어요.", 3.0, 3.8),
    SATISFIED("대체로 만족해요.", 3.8, 4.4),
    VERY_SATISFIED("정말 만족했어요.", 4.4, 5.1);
    private final String description;
    private final double min;
    private final double max;

    SatisfactionLevel(String description, double min, double max) {
        this.description = description;
        this.min = min;
        this.max = max;
    }

    public static String getDescriptionByAverage(double average){
        return java.util.Arrays.stream(values())
                .filter(level -> {
                    if (level == VERY_SATISFIED) {
                        return average >= level.min && average <= level.max;
                    }
                    return average >= level.min && average < level.max;
                })
                .map(level -> level.description)
                .findFirst()
                .orElse("데이터가 부족해요");
    }
}
