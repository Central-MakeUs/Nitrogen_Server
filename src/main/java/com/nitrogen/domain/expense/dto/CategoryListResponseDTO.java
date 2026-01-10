package com.nitrogen.domain.expense.dto;

import java.util.List;

public record CategoryListResponseDTO(
        Long id,
        String name,
        List<SubCategoryResponseDTO> subCategories
) {}
