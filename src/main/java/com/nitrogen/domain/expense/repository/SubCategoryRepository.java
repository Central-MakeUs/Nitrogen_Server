package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.expense.entity.SubCategory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubCategoryRepository extends JpaRepository<SubCategory, Long> {
    long countByParentCategory(Category parent);
    boolean existsBySubCategoryNameAndParentCategory(String name, Category parent);
}
