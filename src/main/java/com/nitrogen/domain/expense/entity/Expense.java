package com.nitrogen.domain.expense.entity;

import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Expense {

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

}
