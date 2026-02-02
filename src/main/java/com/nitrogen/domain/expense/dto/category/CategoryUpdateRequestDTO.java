package com.nitrogen.domain.expense.dto.category;

import com.nitrogen.domain.expense.entity.enums.CategoryIconType;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CategoryUpdateRequestDTO {
    @NotBlank(message = "수정할 카테고리 이름을 입력해주세요.")
    private String name;

    private CategoryIconType icon;
}
