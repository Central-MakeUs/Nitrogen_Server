package com.nitrogen.domain.expense.service.inquiry;

import com.nitrogen.domain.expense.dto.calendar.MonthlyAmountDTO;
import com.nitrogen.domain.expense.dto.report.summary.MonthlyReportSummaryResponse;
import com.nitrogen.domain.expense.repository.ExpenseRepository;
import com.nitrogen.domain.user.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ExpenseInquiryServiceTest {

    @Mock
    UserRepository userRepository;
    @Mock
    ExpenseRepository expenseRepository;
    @InjectMocks
    ExpenseInquiryService expenseInquiryService;

    private MonthlyAmountDTO createMonthlyAmountDTO(String month, Long totalAmount) {
        MonthlyAmountDTO dto = mock(MonthlyAmountDTO.class);
        when(dto.getMonth()).thenReturn(month);
        when(dto.getTotalAmount()).thenReturn(totalAmount);
        return dto;
    }

    @Test
    @DisplayName("N+1 유발 메서드를 사용하지 않고 단일 쿼리 방식으로 조회한다")
    void getMonthlyTotalList_단일_쿼리로_조회() {
        // given
        Long userId = 1L;
        int monthCount = 3;
        List<MonthlyAmountDTO> mockData = List.of(
                createMonthlyAmountDTO("2026-03-01", 150000L),
                createMonthlyAmountDTO("2026-02-01", 200000L),
                createMonthlyAmountDTO("2026-01-01", 100000L)
        );
        when(expenseRepository.findMonthlyTotalsByUserId(userId)).thenReturn(mockData);

        // when
        List<MonthlyReportSummaryResponse> result = expenseInquiryService.getMonthlyTotalList(userId);

        // then — 쿼리 횟수 검증
        verify(expenseRepository, times(1)).findMonthlyTotalsByUserId(userId);
        verify(expenseRepository, never()).findDistinctMonthsByUserId(anyLong());
        verify(expenseRepository, never()).calculateMonthlyTotal(anyLong(), any(), any());

        System.out.println("=== N+1 쿼리 해소 검증 ===");
        System.out.println("테스트 월 수: " + monthCount + "개월");
        System.out.println("[개선 전] 예상 쿼리 수: " + (1 + monthCount) + "회 (findDistinctMonths 1회 + calculateMonthlyTotal " + monthCount + "회)");
        System.out.println("[개선 후] 실제 쿼리 수: 1회 (findMonthlyTotalsByUserId 1회)");
        System.out.println("findMonthlyTotalsByUserId 호출: 1회 — OK");
        System.out.println("findDistinctMonthsByUserId 호출: 0회 — OK");
        System.out.println("calculateMonthlyTotal    호출: 0회 — OK");
    }

    @Test
    @DisplayName("월별 총액 리스트 DTO 매핑이 정확하다")
    void getMonthlyTotalList_DTO_매핑_정합성() {
        // given
        Long userId = 1L;
        List<MonthlyAmountDTO> mockData = List.of(
                createMonthlyAmountDTO("2026-03-01", 150000L),
                createMonthlyAmountDTO("2026-01-01", 100000L)
        );

        when(expenseRepository.findMonthlyTotalsByUserId(userId)).thenReturn(mockData);

        // when
        List<MonthlyReportSummaryResponse> result = expenseInquiryService.getMonthlyTotalList(userId);

        // then
        assertEquals(2, result.size());

        MonthlyReportSummaryResponse march = result.get(0);
        assertEquals("26", march.year());
        assertEquals("3", march.month());
        assertEquals(150000L, march.totalAmount());

        MonthlyReportSummaryResponse january = result.get(1);
        assertEquals("26", january.year());
        assertEquals("1", january.month());
        assertEquals(100000L, january.totalAmount());

        System.out.println("=== DTO 매핑 정합성 검증 ===");
        for (MonthlyReportSummaryResponse r : result) {
            System.out.printf("  %s년 %s월 → totalAmount: %,d원, isOpened: %s%n",
                    r.year(), r.month(), r.totalAmount(), r.isOpened());
        }
    }

    @Test
    @DisplayName("지출 기록이 없으면 빈 리스트를 반환한다")
    void getMonthlyTotalList_지출없으면_빈리스트() {
        // given
        Long userId = 1L;
        when(expenseRepository.findMonthlyTotalsByUserId(userId)).thenReturn(List.of());

        // when
        List<MonthlyReportSummaryResponse> result = expenseInquiryService.getMonthlyTotalList(userId);

        // then
        assertTrue(result.isEmpty());
        verify(expenseRepository, times(1)).findMonthlyTotalsByUserId(userId);
        verify(expenseRepository, never()).calculateMonthlyTotal(anyLong(), any(), any());

        System.out.println("=== 빈 데이터 검증 ===");
        System.out.println("반환 결과: " + result.size() + "건 (빈 리스트)");
        System.out.println("불필요한 쿼리 호출: 0회 — OK");
    }
}
