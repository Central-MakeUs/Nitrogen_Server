package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.CategoryDetailsDTO;
import com.nitrogen.domain.expense.dto.CategoryListResponse;
import com.nitrogen.domain.expense.service.category.CategoryService;
import com.nitrogen.global.apiPayload.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/expense")
@RequiredArgsConstructor
public class CategoryController {

    private final CategoryService categoryService;

    // 카테고리 목록 조회
    @GetMapping("/category_list")
    public ApiResponse<List<CategoryListResponse>> getCategoryList(@RequestParam(name = "userId") Long userId) {
        List<CategoryListResponse> responses = categoryService.getAllCategories(userId);
        return ApiResponse.onSuccess(responses);
    }

    // 커스텀 카테고리 생성
    @PostMapping("/category_create")
    public ApiResponse<Long> createCategory(@RequestBody CategoryDetailsDTO dto,
                                            @RequestParam(name = "userId") Long userId) {
        Long categoryId = categoryService.registerCategory(dto, userId);
        return ApiResponse.onSuccess(categoryId);
    }

    // 커스텀 카테고리 수정 (PATCH)
}
