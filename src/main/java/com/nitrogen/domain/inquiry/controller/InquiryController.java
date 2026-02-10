package com.nitrogen.domain.inquiry.controller;

import com.nitrogen.domain.inquiry.entity.InquiryRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/inquiry")
@RequiredArgsConstructor
@Tag(name = "Inquiry", description = "1:1 문의 API (애플 심사 대응)")
public class InquiryController {

    private final JavaMailSender mailSender;

    @PostMapping("/send")
    @Operation(summary = "1:1 문의 메일 발송")
    public ResponseEntity<String> sendInquiry(@RequestBody InquiryRequest request) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo("nitrogencharger@gmail.com"); // 관리자 이메일
        message.setText("작성자: " + request.userEmail() + "\n\n문의 내용:\n" + request.content());

        mailSender.send(message);

        return ResponseEntity.ok("문의가 메일로 전달되었습니다.");
    }
}
