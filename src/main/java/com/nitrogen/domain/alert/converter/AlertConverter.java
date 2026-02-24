package com.nitrogen.domain.alert.converter;

import com.nitrogen.domain.alert.dto.AlertResponseDTO;
import com.nitrogen.domain.alert.entity.Alert;
import jakarta.persistence.Converter;

import java.util.List;
import java.util.stream.Collectors;

public class AlertConverter {

    public static AlertResponseDTO toAlertResponseDTO(Alert alert) {
        return AlertResponseDTO.builder()
                .alertId(alert.getId())
                .title(alert.getTitle())
                .message(alert.getMessage())
                .isRead(alert.isRead())
                .redirectUrl(alert.getRedirectUrl())
                .createdAt(alert.getCreatedAt())
                .alertType(alert.getAlertType())
                .build();
    }

    public static List<AlertResponseDTO> toAlertResponseDTOList(List<Alert> alerts) {
        return alerts.stream()
                .map(AlertConverter::toAlertResponseDTO)
                .collect(Collectors.toList());
    }
}