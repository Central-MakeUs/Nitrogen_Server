package com.nitrogen.domain.expense.service.init;

import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.enums.BasicCategory;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final CategoryRepository categoryRepository;

    @Override
    @Transactional
    public void run(String... args) {
        if (categoryRepository.count() > 0) return;

        for (BasicCategory basic : BasicCategory.values()) {
            if (basic == BasicCategory.CUSTOM) continue;

            Category category = Category.builder()
                    .name(basic.getDefaultName())
                    .category(basic)
                    .user(null)
                    .build();
            categoryRepository.save(category);
        }
    }

    private String getCategoryKoreanName(BasicCategory basic) {
        return switch (basic) {
            case FOOD -> "식비";
            case CAFE -> "카페";
            case SUBSCRIPTION -> "구독";
            case EDUCATION -> "교육";
            case BEAUTY -> "미용";
            case ENTERTAINMENT -> "유흥";
            case SHOPPING -> "쇼핑";
            default -> basic.name();
        };
    }
}
