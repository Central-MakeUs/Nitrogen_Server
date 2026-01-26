package com.nitrogen.domain.expense.entity.enums;

import java.util.List;
import java.util.Random;

public enum EvaluationFeedback {
    VERY_DISAPPOINTED(1.0, 2.0, "별로였어요.", List.of(
            "결과적으로는 돈 쓴 보람이 크진 않았어요.", "지나고 보니 굳이 안 해도 됐을 소비였어요.",
            "당시엔 괜찮아 보였는데, 지금 보면 아쉬워요.", "결제할 땐 몰랐는데, 남은 건 아쉬움이었어요.",
            "다시 돌아보면 조금 말리고 싶은 선택이에요.", "생각보다 기억에 남지 않는 소비였어요.",
            "이 소비는 시간 지나니 힘이 빠졌어요.", "만족보다는 아쉬운 쪽에 가까웠어요.",
            "결과만 보면 조금 서두른 느낌이에요.", "다음엔 비슷한 상황에서 한 번 더 생각해볼 것 같아요."
    )),
    DISAPPOINTED(2.0, 3.0, "조금 아쉬워요.", List.of(
            "나쁘진 않았지만, 딱 그만큼이었어요.", "크게 후회는 없지만, 엄청 잘 썼다는 느낌도 아니에요.",
            "있었으니까 한 거지, 없었어도 괜찮았을 소비였어요.", "생각해보면 조금 더 신중해도 됐을 것 같아요.",
            "그냥 지나간 소비에 가까웠어요.", "기대보단 조금 못 미쳤어요.",
            "만족과 아쉬움 사이, 중간쯤이었어요.", "딱히 문제는 없지만, 기억에 남지도 않아요.",
            "‘괜찮다’보다는 ‘그럭저럭’에 가까워요.", "다시 한다면 굳이 안 해도 될 것 같아요."
    )),
    NORMAL(3.0, 3.8, "그냥 그랬어요.", List.of(
            "특별한 감정 없이 무난하게 지나갔어요.", "기대한 만큼, 딱 그 정도였어요.",
            "크게 만족도, 아쉬움도 없는 평범한 소비였어요.", "기억에 오래 남지는 않지만, 문제 될 건 없어요.",
            "예상 범위 안에서 끝난 소비였어요.", "그냥 한 번의 소비로 정리되는 느낌이에요.",
            "좋지도 나쁘지도 않은, 중간쯤이었어요.", "이 소비에 대해선 할 말이 많지 않아요.",
            "지나고 나서도 크게 생각나지 않아요.", "무난하게 쓰고, 무난하게 지나갔어요."
    )),
    SATISFIED(3.8, 4.4, "대체로 만족해요.", List.of(
            "전반적으로 보면 괜찮은 선택이었어요.", "다시 비슷한 상황이면 또 할 것 같아요.",
            "크게 고민할 필요는 없었던 소비였어요.", "기대보다 나쁘지 않았어요.",
            "만족 쪽에 조금 더 가까웠어요.", "무난하지만, 좋은 쪽의 무난함이었어요.",
            "결과를 보면 잘 고른 편이에요.", "이 정도면 충분히 괜찮았어요.",
            "쓰고 나서 후회는 없었어요.", "다음에도 비슷하면 고민 없이 할 것 같아요."
    )),
    VERY_SATISFIED(4.4, 5.01, "정말 만족했어요.", List.of(
            "지나고 보니 잘 썼다는 생각이 들어요.", "이건 꽤 기억에 남는 소비였어요.",
            "돈 아깝다는 생각은 전혀 안 들었어요.", "다시 돌아가도 같은 선택을 할 것 같아요.",
            "이 소비만큼은 후회가 없어요.", "생각날 때마다 잘 샀다는 느낌이에요.",
            "만족도 면에서는 확실히 좋았어요.", "이건 소비가 아니라 경험처럼 남았어요.",
            "결과까지 봤을 때 정말 괜찮았어요.", "이런 소비는 자주 있어도 좋을 것 같아요."
    ));

    private final double min;
    private final double max;
    private final String label;
    private final List<String> sentences;

    EvaluationFeedback(double min, double max, String label, List<String> sentences) {
        this.min = min;
        this.max = max;
        this.label = label;
        this.sentences = sentences;
    }

    public static String getRandomSentence(double score) {
        for (EvaluationFeedback feedback : values()) {
            if (score >= feedback.min && score < feedback.max) {
                int randomIndex = new Random().nextInt(feedback.sentences.size());
                return feedback.sentences.get(randomIndex);
            }
        }
        return "데이터가 부족하여 분석할 수 없습니다."; // 기본값
    }
}
