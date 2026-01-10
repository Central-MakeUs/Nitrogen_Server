package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CategoryRepository extends JpaRepository<Category, Long> {

    boolean existsByCategoryName(String name);
}
