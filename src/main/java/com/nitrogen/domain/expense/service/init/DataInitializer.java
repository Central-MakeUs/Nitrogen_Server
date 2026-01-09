package com.nitrogen.domain.expense.service.init;

import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.SubCategory;
import com.nitrogen.domain.expense.entity.enums.BasicCategory;
import com.nitrogen.domain.expense.repository.CategoryRepository;
import com.nitrogen.domain.expense.repository.SubCategoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final CategoryRepository categoryRepository;
    private final SubCategoryRepository subCategoryRepository;

    @Override
    @Transactional
    public void run(String... args) {
        if (categoryRepository.count() > 0) return;

        for (BasicCategory basic : BasicCategory.values()) {
            if (basic == BasicCategory.CUSTOM) continue;

            Category category = Category.builder()
                    .name(getKoreanName(basic))
                    .category(basic)
                    .user(null)
                    .build();
            categoryRepository.save(category);

            for (int i = 1; i <= 3; i++) {
                SubCategory sub = SubCategory.builder()
                        .subCategoryName(category.getName() + " 세부 " + i) // 이름 전달받으면 수정하기
                        .parentCategory(category)
                        .build();
                subCategoryRepository.save(sub);
            }
        }
    }

    private List<String> getKoreanName(BasicCategory basic) {
        return switch (basic) {
            case FOOD -> List.of("외식", "장보기", "야식");
            case CAFE -> List.of("커피", "빵", "스타벅스");
            case SUBSCRIPTION -> List.of("동영상", "노래", "뉴스");
            case EDUCATION -> List.of("강의", "도서", "자격증");
            case BEAUTY -> List.of("머리", "피부", "화장품");
            case ENTERTAINMENT -> List.of("술", "노래방", "보드게임");
            case SHOPPING -> List.of("옷", "생활용품", "굿즈");
            default -> List.of("기타 1", "기타 2", "기타 3");
        };
    }
}
