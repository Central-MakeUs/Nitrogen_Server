package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.dto.calendar.DailyAmountDTO;
import com.nitrogen.domain.expense.dto.calendar.MonthlyAmountDTO;
import com.nitrogen.domain.expense.entity.Expense;
import com.nitrogen.domain.expense.entity.enums.EmotionType;
import com.nitrogen.domain.expense.entity.enums.EvaluationType;
import com.nitrogen.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;

import java.util.List;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {
    // 특정 날짜 지출내역 최신순 조회
    @Query("SELECT e FROM Expense e JOIN FETCH e.category WHERE e.user.userId = :userId AND e.expendedAt = :expendedAt " + "ORDER BY e.id DESC")
    List<Expense> findAllByUserUserIdAndExpendedAtWithCategory(@Param("userId") Long userId, @Param("expendedAt") LocalDate expendedAt);

    // 월별 총액을 위한 계산
    @Query("SELECT COALESCE(SUM(e.amount), 0) FROM Expense e WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    long calculateMonthlyTotal(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end);

    // 특정 기간 내 사용자의 지출 내역 조회
    @Query("SELECT e FROM Expense e JOIN FETCH e.category WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    List<Expense> findAllByUserIdAndExpendedAtBetweenWithCategory(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end);

    // 특정 기간 내 만족도 별 사용자의 지출 내역 조회
    @Query("SELECT e FROM Expense e JOIN FETCH e.category WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end AND e.evaluationType = :evaluationType")
    List<Expense> findExpensesWithCategory(
            @Param("userId") Long userId,
            @Param("start") LocalDate start,
            @Param("end") LocalDate end,
            @Param("evaluationType") EvaluationType evaluationType
    );

    // 특정 기간 내 특정 감정 내 소비 항목 TOP 3 조회
    @Query(value = "SELECT * FROM expense e " +
            "WHERE e.user_id = :userId AND e.expended_at BETWEEN :start AND :end " +
            "AND e.emotion_type = :emotionType " +
            "ORDER BY e.amount DESC LIMIT 3", nativeQuery = true)
    List<Expense> findTop3ByEmotion(@Param("userId") Long userId,
                                    @Param("start") LocalDate start,
                                    @Param("end") LocalDate end,
                                    @Param("emotionType") String emotionType);

    // 평균 만족도 점수 계산
    @Query("SELECT COALESCE(AVG(CASE " +
            "WHEN e.evaluationType = com.nitrogen.domain.expense.entity.enums.EvaluationType.VERY_SATISFIED THEN 5.0 " +
            "WHEN e.evaluationType = com.nitrogen.domain.expense.entity.enums.EvaluationType.SATISFIED THEN 4.0 " +
            "WHEN e.evaluationType = com.nitrogen.domain.expense.entity.enums.EvaluationType.NORMAL THEN 3.0 " +
            "WHEN e.evaluationType = com.nitrogen.domain.expense.entity.enums.EvaluationType.DISAPPOINTED THEN 2.0 " +
            "WHEN e.evaluationType = com.nitrogen.domain.expense.entity.enums.EvaluationType.VERY_DISAPPOINTED THEN 1.0 " +
            "ELSE 0.0 END), 0.0) " +
            "FROM Expense e WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end")
    double calculateAverageSatisfactionScore(@Param("userId") Long userId,
                                           @Param("start") LocalDate start,
                                           @Param("end") LocalDate end);

    // 전체기간 기준 소비기록 존재 여부
    boolean existsByUserUserId(Long userId);

    // 일별 지출 합계 계산
    @Query("SELECT new com.nitrogen.domain.expense.dto.calendar.DailyAmountDTO(e.expendedAt, SUM(e.amount)) " +
            "FROM Expense e " +
            "WHERE e.user.userId = :userId AND e.expendedAt BETWEEN :start AND :end " +
            "GROUP BY e.expendedAt " +
            "ORDER BY e.expendedAt ASC")
    List<DailyAmountDTO> calculateDailyTotals(
            @Param("userId") Long userId,
            @Param("start") LocalDate start,
            @Param("end") LocalDate end
    );

    // 사용자가 지출한 월 목록 조회(내림차순)
    @Query("SELECT DISTINCT FUNCTION('DATE_FORMAT', e.expendedAt, '%Y-%m-01') " +
            "FROM Expense e WHERE e.user.userId = :userId " +
            "ORDER BY e.expendedAt DESC")
    List<String> findDistinctMonthsByUserId(@Param("userId") Long userId);

    // 사용자의 월별 지출 합계 조회 (월 목록 + 합계를 한 번에)
    @Query(value = "SELECT DATE_FORMAT(e.expended_at, '%Y-%m-01') AS month, SUM(e.amount) AS totalAmount " +
            "FROM expense e WHERE e.user_id = :userId " +
            "GROUP BY month ORDER BY month DESC", nativeQuery = true)
    List<MonthlyAmountDTO> findMonthlyTotalsByUserId(@Param("userId") Long userId);

    // 유저의 지출 중 오늘 이전 날짜이면서 아직 평가가 되지 않은 것이 있는지 확인
    boolean existsByEvaluationTypeIsNullAndUserAndExpendedAtBefore(User user, LocalDate date);

    boolean existsByUserUserIdAndExpendedAtBetween(Long userId, LocalDate start, LocalDate end);
}
