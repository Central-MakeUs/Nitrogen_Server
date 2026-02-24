package com.nitrogen.domain.alert.dto;

import com.nitrogen.domain.alert.entity.Alert;
import com.nitrogen.domain.alert.entity.enums.AlertType;

import java.time.LocalDateTime;

public record AlertResponseDTO(
        Long alertId,
        AlertType alertType,
        String title,
        String message,
        String redirectUrl,
        boolean isRead,
        LocalDateTime createdAt
) {
    public static AlertResponseDTO from(Alert alert) {
        return new AlertResponseDTO(
                alert.getId(),
                alert.getAlertType(),
                alert.getTitle(),
                alert.getMessage(),
                alert.getRedirectUrl(),
                alert.isRead(),
                alert.getCreatedAt()
        );
    }
}
