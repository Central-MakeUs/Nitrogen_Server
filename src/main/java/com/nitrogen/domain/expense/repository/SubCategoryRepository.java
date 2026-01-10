package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.SubCategory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubCategoryRepository extends JpaRepository<SubCategory, Long> {
    long countByParentCategory(Category parent);
    boolean existsBySubCategoryName(String name); // 서브 카테고리 이름 중복 체크용
}
