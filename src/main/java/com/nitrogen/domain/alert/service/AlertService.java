package com.nitrogen.domain.alert.service;


import com.nitrogen.domain.alert.converter.AlertConverter;
import com.nitrogen.domain.alert.dto.AlertResponseDTO;
import com.nitrogen.domain.alert.entity.Alert;
import com.nitrogen.domain.alert.repository.AlertRepository;
import com.nitrogen.domain.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AlertService {

    private final AlertRepository alertRepository;

    public List<AlertResponseDTO> getAlertList(User user){
        List<Alert> alerts = alertRepository.findAllByUserOrderByCreatedAtDesc(user);
        return AlertConverter.toAlertResponseDTOList(alerts);
    }

    @Transactional
    public void markAsRead(Long alertId, User user){
        Alert alert = alertRepository.findById(alertId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 알림입니다."));

        if(!alert.getUser().getUserId().equals(user.getUserId())){
            throw new IllegalStateException("해당 알림에 대한 권한이 없습니다.");
        }
        alert.markAsRead();
    }

    @Transactional
    public void markAllAsRead(User user) {
        List<Alert> unreadAlerts = alertRepository.findAllByUserAndIsReadFalse(user);
        unreadAlerts.forEach(Alert::markAsRead);
    }
}
