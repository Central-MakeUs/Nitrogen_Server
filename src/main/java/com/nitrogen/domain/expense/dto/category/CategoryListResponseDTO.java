package com.nitrogen.domain.expense.dto.category;

import com.nitrogen.domain.expense.entity.enums.CategoryIconType;

import java.util.List;

public record CategoryListResponseDTO(
        Long id,
        String name,
        CategoryIconType icon
) {}
