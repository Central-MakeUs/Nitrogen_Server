package com.nitrogen.domain.expense.service.category;

import com.nitrogen.domain.expense.dto.CategoryDetailsDTO;
import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AddCategory {
    private final CategoryRepository categoryRepository;
    private final UserRepository userRepository;

    public String registerCategory(CategoryDetailsDTO dto, Long userId){
        // 해당 예외처리가 꼭 필요할까요? 궁금
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        // 중복된 카테고리명이면 예외처리(이미 존재하는 카테고리)
        Category categoryname = categoryRepository.findByCategoryName(dto.getName())
                .orElseThrow(()-> new IllegalArgumentException("이미 존재하는 카테고리명입니다."));


        Category category = Category.builder()
                .name(dto.getName())
                .category(categoryname.getCategory())
                .user(user)
                .build();
        Category saved = categoryRepository.save(category);

        return saved.getName();
    }
}
