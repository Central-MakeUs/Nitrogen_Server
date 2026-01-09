package com.nitrogen.domain.expense.dto;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import jakarta.validation.constraints.NotNull;
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

    private Long subCategoryId;

    @NotNull(message = "소비 감정은 필수 선택 사항입니다.")
    private EmotionType emotionType;
}
