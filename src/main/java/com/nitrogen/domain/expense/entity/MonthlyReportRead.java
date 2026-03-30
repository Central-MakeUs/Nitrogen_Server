package com.nitrogen.domain.expense.entity;

import com.nitrogen.domain.user.entity.User;
import com.nitrogen.global.common.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Table(name = "monthly_report_read",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "report_month"}))
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class MonthlyReportRead extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDate reportMonth; // 해당 월의 1일 (e.g., 2025-02-01)

    public MonthlyReportRead(User user, LocalDate reportMonth) {
        this.user = user;
        this.reportMonth = reportMonth;
    }
}