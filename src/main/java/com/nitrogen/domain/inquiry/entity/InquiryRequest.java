package com.nitrogen.domain.inquiry.entity;

public record InquiryRequest(
        String content,
        String userEmail // 답변 받을 유저 이메일
) {}
