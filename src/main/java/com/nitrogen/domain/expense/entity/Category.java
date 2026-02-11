package com.nitrogen.domain.expense.entity;

import com.nitrogen.domain.expense.entity.enums.BasicCategory;
import com.nitrogen.domain.expense.entity.enums.CategoryIconType;
import com.nitrogen.domain.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Category {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Enumerated(EnumType.STRING)
    private BasicCategory category;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "category_icon_type", nullable = false)
    private CategoryIconType categoryIconType;

    @OneToMany(mappedBy = "category", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Expense> expenses = new ArrayList<>();

    public void updateName(String newName) {
        if (newName == null || newName.isBlank()) {
            throw new IllegalArgumentException("이름은 비어있을 수 없습니다.");
        }
        this.name = newName;
    }

    public void updateIcon(CategoryIconType newIcon) {
        if (newIcon != null) {
            this.categoryIconType = newIcon;
        }
    }
}
