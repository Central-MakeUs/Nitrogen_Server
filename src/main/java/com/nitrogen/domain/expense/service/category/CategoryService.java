package com.nitrogen.domain.expense.service.category;

import com.nitrogen.domain.expense.dto.category.CategoryDetailsDTO;
import com.nitrogen.domain.expense.dto.category.CategoryListResponseDTO;
import com.nitrogen.domain.expense.dto.category.CategoryUpdateRequestDTO;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.enums.BasicCategory;
import com.nitrogen.domain.expense.entity.enums.CategoryIconType;
import com.nitrogen.domain.expense.repository.CategoryRepository;
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
    private final UserRepository userRepository;

    // 카테고리 추가
    @Transactional
    public Long registerCategory(CategoryDetailsDTO dto, Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        if (categoryRepository.existsByNameAndUserId(dto.getName(), userId)) {
            throw new IllegalArgumentException("이미 존재하는 카테고리 이름입니다.");
        }

        Category newCategory = Category.builder()
                .name(dto.getName())
                .category(BasicCategory.CUSTOM) // 기본 7종 외에는 모두 CUSTOM
                .categoryIconType(dto.getIcon())
                .user(user)
                .build();

        return categoryRepository.save(newCategory).getId();
    }


    // 카테고리 조회
    @Transactional(readOnly = true)
    public List<CategoryListResponseDTO> getAllCategories(Long userId) {
        // fetch join
        List<Category> categories = categoryRepository.findAllByUserId(userId);

        return categories.stream()
                .map(cat -> new CategoryListResponseDTO(
                        cat.getId(),
                        cat.getName(),
                        cat.getCategoryIconType()
                ))
                .collect(Collectors.toList());
    }

    // 카테고리 수정(기본 + 커스텀)
    @Transactional
    public Long updateCategory(Long categoryId, CategoryUpdateRequestDTO dto){
        Category category = categoryRepository.findById(categoryId)
                .orElseThrow(() -> new IllegalArgumentException("해당 카테고리가 존재하지 않습니다."));

        category.updateName(dto.getName());
/*
아이콘 수정 로직 확장 기능 오픈 시 재오픈 예정
 */
//        if (dto.getIcon() != null) {
//            category.updateIcon(dto.getIcon());
//        }

        return category.getId();
    }

    @Transactional
    public void initUserCategories(User user) {

        if (categoryRepository.existsByUser(user)) return;

        for (BasicCategory basic : BasicCategory.values()) {
            if (basic == BasicCategory.CUSTOM) continue;

            Category category = Category.builder()
                    .name(basic.getDefaultName())
                    .category(basic)
                    .user(user)
                    .categoryIconType(CategoryIconType.PLUS)
                    .build();
            categoryRepository.save(category);
        }
    }
}