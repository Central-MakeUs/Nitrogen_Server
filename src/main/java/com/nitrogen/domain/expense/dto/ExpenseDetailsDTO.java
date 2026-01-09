package com.nitrogen.domain.expense.dto;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
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
    private int amount;
    private LocalDate expendedAt;
    private Long categoryId;
    private Long subCategoryId;
    private EmotionType emotionType;
}
