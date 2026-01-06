package com.nitrogen.global.s3.service;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ObjectMetadata;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class S3ImageUploader {

    private final AmazonS3 amazonS3;

    @Value("${cloud.aws.s3.bucket}")
    private String bucket;

    // 이미지 업로드
    public String uploadImage(MultipartFile file, String dirName){

        if (file == null || file.isEmpty()) {
            return null; // 혹은 예외 던지기
        }

        String filename = UUID.randomUUID() + "_" + file.getOriginalFilename();
        String s3Key = dirName + "/" + filename;

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(file.getSize());
        metadata.setContentType(file.getContentType());

        try {
            amazonS3.putObject(bucket, s3Key, file.getInputStream(), metadata);
            return amazonS3.getUrl(bucket, s3Key).toString();
        } catch (IOException e) {
            throw new RuntimeException("S3 파일 업로드 실패: " + e.getMessage());
        }
    }

    // 이미지 삭제
    public void deleteImage(String originalFilename)  {
        amazonS3.deleteObject(bucket, originalFilename);
    }
}
