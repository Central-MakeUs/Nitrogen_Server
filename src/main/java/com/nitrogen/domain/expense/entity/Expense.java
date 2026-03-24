package com.nitrogen.domain.expense.entity;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "expense", indexes = {
        @Index(name = "idx_user_expended_at", columnList = "user_id, expended_at")
})
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Expense extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // 지출기록 구분키

    private int amount; // 지출 금액
    private LocalDate expendedAt; // 지출 일자

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", nullable = false)
    private Category category; // 카테고리

    @Enumerated(EnumType.STRING)
    private EmotionType emotionType; // 소비감정

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user; // 지출기록 유저

    @Enumerated(EnumType.STRING)
    private EvaluationType evaluationType; // 소비 회고

    public void updateEvaluation(EvaluationType evaluationType) {
        this.evaluationType = evaluationType;
    }

    @Column(nullable = false, length = 40)
    private String usageHistory;

    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    public void updateExpenseRecord(Integer newAmount, String newUsageHistory, LocalDate newExpendedAt, Category newCategory) {
        if (newAmount == null || newAmount.intValue() <= 0) {
            throw new IllegalArgumentException("금액은 0보다 커야 합니다.");
        }
        this.amount = newAmount;
        this.usageHistory = newUsageHistory;
        this.expendedAt = newExpendedAt;
        this.category = newCategory;
    }
}
