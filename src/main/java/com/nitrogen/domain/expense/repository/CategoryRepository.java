package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CategoryRepository extends JpaRepository<Category, Long> {

    boolean existsByCategoryName(String name);

    @Query("SELECT DISTINCT c FROM Category c " +
            "LEFT JOIN FETCH c.subCategories " +
            "WHERE c.user.id = :userId")
    List<Category> findAllByUserId(@Param("userId") Long userId);
}
