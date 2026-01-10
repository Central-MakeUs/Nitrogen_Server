package com.nitrogen.domain.expense.dto;

import jakarta.persistence.Entity;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class CategoryDetailsDTO {
    private String name;
    private Long parentCategoryId; // 서브 카테고리를 만들 때만 상위 카테고리 ID를 보냄
}
