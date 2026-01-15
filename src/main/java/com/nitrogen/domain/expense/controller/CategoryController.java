package com.nitrogen.domain.expense.controller;

import com.nitrogen.domain.expense.dto.category.CategoryDetailsDTO;
import com.nitrogen.domain.expense.dto.category.CategoryListResponseDTO;
import com.nitrogen.domain.expense.dto.category.CategoryUpdateRequestDTO;
import com.nitrogen.domain.expense.service.category.CategoryService;
import com.nitrogen.global.apiPayload.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/expense")
@RequiredArgsConstructor
public class CategoryController {

    private final CategoryService categoryService;

    // 카테고리 목록 조회
    @GetMapping("/category_list")
    @Operation(summary = "카테고리 조회", description = "지출을 쓰기 전에 사용자가 선택할 카테고리 리스트(기본 7종 + 커스텀)를 서버에서 내려줘야 합니다.")
    public ApiResponse<List<CategoryListResponseDTO>> getCategoryList(@RequestParam(name = "userId") Long userId) {
        List<CategoryListResponseDTO> responses = categoryService.getAllCategories(userId);
        return ApiResponse.onSuccess(responses);
    }

    // 커스텀 카테고리 생성
    @PostMapping("/category_create")
    @Operation(summary = "카테고리 직접추가", description = "유저가 직접 카테고리를 추가합니다.")
    public ApiResponse<Long> createCategory(@RequestBody CategoryDetailsDTO dto,
                                            @RequestParam(name = "userId") Long userId) {
        Long categoryId = categoryService.registerCategory(dto, userId);
        return ApiResponse.onSuccess(categoryId);
    }

    // 카테고리 수정 (PATCH)
    @Operation(summary = "카테고리 수정", description = "유저가 직접 카테고리를 수정합니다.")
    @PatchMapping("/category_update/{categoryId}")
    public ApiResponse<Long> updateCategory(
            @PathVariable Long categoryId,
            @RequestBody CategoryUpdateRequestDTO dto) {

        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException("카테고리 이름은 비어있을 수 없습니다.");
        }

        Long updatedId = categoryService.updateCategory(categoryId, dto);

        return ApiResponse.onSuccess(updatedId);
    }
}
