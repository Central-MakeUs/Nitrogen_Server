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
                    .name(getCategoryKoreanName(basic))
                    .category(basic)
                    .user(null)
                    .build();
            categoryRepository.save(category);

            List<String> subNames = getSubCategoryNames(basic);

            for (String subName : subNames) {
                SubCategory sub = SubCategory.builder()
                        .subCategoryName(subName)
                        .parentCategory(category)
                        .build();
                subCategoryRepository.save(sub);
            }
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

    private List<String> getSubCategoryNames(BasicCategory basic) {
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
