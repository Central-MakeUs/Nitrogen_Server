package com.nitrogen.domain.expense.repository;

import com.nitrogen.domain.expense.entity.MonthlyReportRead;
import com.nitrogen.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;
import java.util.List;

public interface MonthlyReportReadRepository extends JpaRepository<MonthlyReportRead, Long> {

    boolean existsByUserAndReportMonth(User user, LocalDate reportMonth);

    List<MonthlyReportRead> findAllByUser(User user);
}