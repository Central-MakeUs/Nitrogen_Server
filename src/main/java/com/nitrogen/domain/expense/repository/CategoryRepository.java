package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.Category;
import com.nitrogen.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CategoryRepository extends JpaRepository<Category, Long> {

    @Query("SELECT count(c) > 0 FROM Category c WHERE c.name = :name AND c.user.userId = :userId")
    boolean existsByNameAndUserId(@Param("name") String name, @Param("userId") Long userId);

    @Query("SELECT c FROM Category c WHERE c.user.userId = :userId")
    List<Category> findAllByUserId(@Param("userId") Long userId);

    boolean existsByUser(User user);
}
