package com.nitrogen.domain.expense.dto;

import java.util.List;

public record CategoryListResponse(
        Long id,
        String name,
        List<SubCategoryResponse> subCategories
) {}
