package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.SubCategory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SubCategoryRepository extends JpaRepository<SubCategory, Long> {
}
