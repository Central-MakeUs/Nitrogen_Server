package com.nitrogen.domain.expense.entity.enums;

import java.util.List;
import java.util.Random;

public enum EmotionFeedback {
    VERY_DISAPPOINTED(1.0, 2.0, "별로였어요.", List.of(
            "이번 주 소비는 마음에 와닿지 않았어요.", "소비가 감정과 잘 연결되지 않은 한 주였어요.",
            "돈을 쓰면서도 마음이 채워지지 않았어요.", "소비 속에 감정이 빠져 있던 한 주였어요.",
            "쓰긴 했지만, 마음까지 움직이진 못했어요.", "감정 없이 흘러간 소비가 많았어요.",
            "이번 주 소비엔 마음이 실리지 않았어요.", "소비가 마음과 따로 놀았던 한 주였어요.",
            "돈은 나갔는데, 마음은 비어 있었어요.", "감정적으로 만족스럽지 못한 소비였어요."
    )),
    DISAPPOINTED(2.0, 3.0, "조금 아쉬워요.", List.of(
            "마음이 살짝 움직이긴 했지만, 크게 와닿진 않았어요.", "소비에 감정이 조금 묻어 있긴 했어요.",
            "마음의 흐름과 소비가 약간 엇갈렸어요.", "감정에 솔직한 소비라기엔 살짝 아쉬웠어요.",
            "소비 속에 마음이 희미하게 남아 있어요.", "이번 주는 마음보다 습관이 이끈 소비가 많았어요.",
            "감정을 담기엔 소비가 조금 성급했어요.", "마음의 온도와 소비의 무게가 살짝 달랐어요.",
            "조금 더 마음을 들여다봤으면 달라졌을 소비예요.", "아쉬움이 살짝 남는 한 주의 소비였어요."
    )),
    NORMAL(3.0, 3.8, "그냥 그랬어요.", List.of(
            "무난하게 마음을 따라간 한 주였어요.", "특별한 감정 없이 고르게 소비한 한 주예요.",
            "마음의 파도가 잔잔했던 소비 패턴이에요.", "감정의 기복 없이 평온하게 소비했어요.",
            "이번 주 소비엔 큰 감정의 변화가 없었어요.", "마음이 크게 흔들리지 않은 소비였어요.",
            "감정이 고르게 분포된 평범한 한 주였어요.", "특별히 기억에 남는 감정 소비는 없었어요.",
            "마음의 온도가 일정했던 한 주예요.", "담담하게 지나간 소비의 한 주였어요."
    )),
    SATISFIED(3.8, 4.4, "대체로 만족해요.", List.of(
            "마음이 이끄는 대로 잘 소비한 한 주였어요.", "감정에 솔직한 소비가 돋보였어요.",
            "이번 주 소비엔 마음이 잘 담겨 있어요.", "소비 속에 감정이 자연스럽게 녹아 있었어요.",
            "마음의 흐름과 소비가 잘 맞아떨어졌어요.", "감정을 잘 읽고 소비한 한 주였어요.",
            "마음에 맞는 소비를 꽤 잘 골랐어요.", "이번 주 소비엔 따뜻한 마음이 묻어나요.",
            "감정과 소비가 조화롭게 어우러진 한 주예요.", "마음이 편안했던 소비 패턴이에요."
    )),
    VERY_SATISFIED(4.4, 5.01, "정말 만족했어요.", List.of(
            "마음이 충분히 채워진 소비의 한 주였어요.", "감정에 꼭 맞는 소비를 해낸 한 주예요.",
            "이번 주 소비는 마음까지 풍요로웠어요.", "소비 하나하나에 마음이 가득 담겨 있었어요.",
            "감정적으로 가장 만족스러운 한 주였어요.", "마음이 이끄는 소비가 빛났던 한 주예요.",
            "이번 주 소비엔 행복한 마음이 가득해요.", "감정과 소비가 완벽하게 맞아떨어졌어요.",
            "마음을 잘 돌본 소비의 한 주였어요.", "이렇게 마음에 드는 소비 주간은 드물어요."
    ));

    private final double min;
    private final double max;
    private final String label;
    private final List<String> sentences;

    EmotionFeedback(double min, double max, String label, List<String> sentences) {
        this.min = min;
        this.max = max;
        this.label = label;
        this.sentences = sentences;
    }

    public static String getRandomSentence(double score, long seed) {
        for (EmotionFeedback feedback : values()) {
            if (score >= feedback.min && score < feedback.max) {
                int index = new Random(seed).nextInt(feedback.sentences.size());
                return feedback.sentences.get(index);
            }
        }
        return "데이터가 부족하여 분석할 수 없습니다.";
    }
}
