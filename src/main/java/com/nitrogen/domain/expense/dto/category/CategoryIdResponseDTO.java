package com.nitrogen.domain.expense.dto.category;

import com.nitrogen.domain.expense.entity.enums.CategoryIconType;

public record CategoryIdResponseDTO(
        Long id,
        String name,
        CategoryIconType icon
) {}
