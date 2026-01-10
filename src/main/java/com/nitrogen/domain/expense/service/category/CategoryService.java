package com.nitrogen.domain.expense.service.category;

import com.nitrogen.domain.expense.dto.CategoryDetailsDTO;
import com.nitrogen.domain.expense.dto.CategoryListResponse;
import com.nitrogen.domain.expense.dto.SubCategoryResponse;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.SubCategory;
import com.nitrogen.domain.expense.entity.enums.BasicCategory;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.expense.repository.SubCategoryRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CategoryService {
    private final CategoryRepository categoryRepository;
    private final SubCategoryRepository subCategoryRepository;
    private final UserRepository userRepository;

    // 카테고리 추가
    @Transactional
    public Long registerCategory(CategoryDetailsDTO dto, Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        // 이름 중복방지(상위 + 서브 포함)
        if (categoryRepository.existsByName(dto.getName()) ||
                subCategoryRepository.existsBySubCategoryName(dto.getName())) {
            throw new IllegalArgumentException("이미 존재하는 카테고리 이름입니다.");
        }

        if (dto.getParentCategoryId() == null) {
            Category newCategory = Category.builder()
                    .name(dto.getName())
                    .category(BasicCategory.CUSTOM)
                    .user(user)
                    .build();
            return categoryRepository.save(newCategory).getId();
        }

        else {
            Category parent = categoryRepository.findById(dto.getParentCategoryId())
                    .orElseThrow(() -> new IllegalArgumentException("상위 카테고리가 존재하지 않습니다."));

            long subCount = subCategoryRepository.countByParentCategory(parent);
            if (subCount >= 3) {
                throw new IllegalArgumentException("서브 카테고리는 상위 카테고리당 최대 3개까지만 추가 가능합니다.");
            }

            SubCategory subCategory = SubCategory.builder()
                    .subCategoryName(dto.getName())
                    .parentCategory(parent)
                    .build();
            return subCategoryRepository.save(subCategory).getId();
        }
    }

    // 카테고리 조회
    @Transactional(readOnly = true)
    public List<CategoryListResponse> getAllCategories(Long userId) {
        // fetch join
        List<Category> categories = categoryRepository.findAllByUserId(userId);

        return categories.stream()
                .map(cat -> new CategoryListResponse(
                        cat.getId(),
                        cat.getName(),
                        cat.getSubCategories().stream()
                                .map(sub -> new SubCategoryResponse(sub.getId(), sub.getSubCategoryName()))
                                .collect(Collectors.toList())
                ))
                .collect(Collectors.toList());
    }
}