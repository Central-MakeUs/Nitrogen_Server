package com.nitrogen.domain.alert.service;


import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import com.nitrogen.domain.alert.dto.FCMRequestDTO;
import com.nitrogen.domain.alert.entity.Alert;
import com.nitrogen.domain.alert.entity.enums.AlertType;
import com.nitrogen.domain.alert.repository.AlertRepository;
import com.nitrogen.domain.user.entity.User;
import com.nitrogen.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class FcmService {
    private final AlertRepository alertRepository;
    private final UserRepository userRepository;

    @Transactional
    public void sendAndSaveAlert(FCMRequestDTO fcmRequestDto, AlertType type){

        User user = userRepository.findBySocialId(fcmRequestDto.targetUserId())
                .orElseGet(() -> userRepository.findByAppleSub(fcmRequestDto.targetUserId())
                        .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다.")));

        Alert alert = Alert.builder()
                .user(user)
                .alertType(type)
                .title(fcmRequestDto.title())
                .message(fcmRequestDto.body())
                .redirectUrl(fcmRequestDto.redirectUrl())
                .isRead(false)
                .build();
        alertRepository.save(alert);


        if (user.getFcmToken() != null && !user.getFcmToken().isEmpty()) {
            sendFcmPush(user.getFcmToken(), fcmRequestDto);
        }
    }

    private void sendFcmPush(String token, FCMRequestDTO fcmRequestDto) {
        Message message = Message.builder()
                .setToken(token)
                .setNotification(Notification.builder()
                        .setTitle(fcmRequestDto.title())
                        .setBody(fcmRequestDto.body())
                        .build())
                .putData("url", fcmRequestDto.redirectUrl() != null ? fcmRequestDto.redirectUrl() : "")
                .build();

        try {
            FirebaseMessaging.getInstance().send(message);
        } catch (Exception e) {
            log.error("FCM 발송 에러: " + e.getMessage());
        }
    }
}
