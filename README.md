# 🏗️ System Architecture & Roadmap

## 1. Overall System Design
> 본 프로젝트는 단일 EC2 인스턴스 내에서 **Nginx를 활용한 환경 격리(Isolation)**를 통해 운영 안정성과 개발 효율성을 동시에 확보한 아키텍처를 지향합니다.

## 🛠️ Key Implementation Details

### 🔒 Environment Isolation (Blue-Green Logic)
* **Production (`Port 8080`)**: 실제 유저가 사용하는 안정적인 서비스 환경입니다.
* **Staging/Test (`Port 8081`)**: `FCM`, `Apple Login` 등 신규 기능을 배포 전 검증하는 격리된 테스트 환경입니다.

### 🤖 Automation Workflow
* **`main` 브랜치**: 푸시 시 운영 서버(`application-prod.yml`)로 자동 배포됩니다.
* **`develop` 브랜치**: 푸시 시 테스트 서버(`application-test.yml`)로 자동 배포됩니다.

---

## 🚀 Roadmap (Future Enhancements)
- [ ] **`Containerization`**: Docker 도입을 통한 배포 환경 일관성 확보
- [ ] **`Monitoring`**: Prometheus & Grafana 연동을 통한 실시간 지표 시각화
- [ ] **`Zero-Downtime`**: Nginx 스위칭을 활용한 완전한 무중단 배포 구현

---

## 🛠 Tech Stack

### 🚀 Core
![Spring Boot](https://img.shields.io/badge/SpringBoot-6DB33F?style=for-the-badge&logo=springboot&logoColor=white)
![Java](https://img.shields.io/badge/Java17-007396?style=for-the-badge&logo=java&logoColor=white)
![Gradle](https://img.shields.io/badge/Gradle-02303A?style=for-the-badge&logo=gradle&logoColor=white)

### 🗄 Database & Infra
![MySQL](https://img.shields.io/badge/MySQL8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![JPA](https://img.shields.io/badge/JPA-Hibernate-orange?style=for-the-badge)
![AWS](https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white)

### 📄 API Documentation
![Swagger](https://img.shields.io/badge/Swagger-85EA2D?style=for-the-badge&logo=swagger&logoColor=black)

### Deployment
![CI/CD](https://img.shields.io/badge/GitHubActions-CI%2FCD-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)

![Auto Deploy](https://img.shields.io/badge/Deployment-Automated-success?style=for-the-badge)

![AWS EC2](https://img.shields.io/badge/AWS-EC2-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white)

![Nginx](https://img.shields.io/badge/Nginx-Reverse%20Proxy-009639?style=for-the-badge&logo=nginx&logoColor=white)

![HTTPS](https://img.shields.io/badge/HTTPS-SSL-green?style=for-the-badge&logo=letsencrypt&logoColor=white)

![Domain](https://img.shields.io/badge/Domain-Gabia-FF6B00?style=for-the-badge)

![FCM](https://img.shields.io/badge/FCM-Firebase%20Cloud%20Messaging-FFCA28?style=for-the-badge&logo=firebase&logoColor=black)
---

## 📊 ERD (Entity Relationship Diagram)

<img width="637" height="709" alt="image" src="https://github.com/user-attachments/assets/4dbf6bb0-44a6-4fd5-a85b-285a6adc2140" />
