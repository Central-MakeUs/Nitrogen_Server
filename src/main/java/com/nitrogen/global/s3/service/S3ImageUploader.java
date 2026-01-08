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
            return null;
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
    public void deleteImage(String dirName, String fileName) {
        String s3Key = dirName + "/" + fileName; // 경로와 파일명을 합쳐서 Key 생성

        if (!amazonS3.doesObjectExist(bucket, s3Key)) {
            throw new RuntimeException("삭제할 파일이 S3에 존재하지 않습니다: " + s3Key);
        }

        try {
            amazonS3.deleteObject(bucket, s3Key);
        } catch (Exception e) {
            throw new RuntimeException("S3 파일 삭제 실패: " + e.getMessage());
        }
    }
}
