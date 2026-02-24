package com.nitrogen.domain.alert.entity;

import com.nitrogen.domain.alert.entity.enums.AlertType;
import com.nitrogen.domain.user.entity.User;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Setter;

public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AlertType alertType;

    @Column(length = 500, nullable = false)
    private String title;

    @Column(length = 500, nullable = false)
    private String message;

    @Column(nullable = true)
    private String redirect_url;

    @Column(nullable = false)
    @Builder.Default
    @Setter
    private boolean isRead = false;



}
