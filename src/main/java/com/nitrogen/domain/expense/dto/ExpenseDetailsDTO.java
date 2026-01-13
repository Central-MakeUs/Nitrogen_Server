package com.nitrogen.domain.expense.dto;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class ExpenseDetailsDTO {
    @NotNull(message = "지출 금액은 필수 입력 사항입니다.")
    @Positive(message = "지출 금액은 0보다 커야 합니다.")
    private Integer amount;

    @NotNull(message = "지출 일자는 필수 입력 사항입니다.")
    private LocalDate expendedAt;

    @NotNull(message = "상위 카테고리는 필수 선택 사항입니다.")
    private Long categoryId;

    @NotBlank(message = "사용처 기록은 필수 입력 사항입니다.")
    @Pattern(regexp = "^[a-zA-Z0-9가-힣\\s]{1,20}$", message = "사용처는 한글, 영문, 숫자 포함 최대 20자까지 가능합니다.")
    private String usageHistory;

    @NotNull(message = "소비 감정은 필수 선택 사항입니다.")
    private EmotionType emotionType;
}
