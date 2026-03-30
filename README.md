## 🌿 브랜치 전략(반드시 확인하세요)

| 브랜치 | 용도 | 직접 push |
|--------|------|-----------|
| `develop` | 운영 브랜치 | ❌ 금지 |
| `feature/apple-login-split ` | 기능 개발 브랜치 | ✅ 가능 |

---

## 🔄 작업 플로우

1. `feature/기능명` 브랜치 생성 후 작업
2. 원격에 push
```bash
   git push origin feature/apple-login-split
```
3. GitHub Actions CI/CD 확인
4. GitHub에서 `develop`으로 PR 생성
5. 관리자 승인 후 merge
6. 로컬 `develop` 동기화
```bash
   git checkout develop
   git pull origin develop
```

---

## ⚠️ 주의사항

- `develop` 브랜치 직접 push **금지**
- merge 후 **`Delete branch` 버튼 클릭 절대 금지** (테스트 서버 연결된 브랜치)
- force push **금지**

<br>

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

![FCM](https://img.shields.io/badge/FCM-Push%20Notification-FFCA28?style=for-the-badge&logo=firebase&logoColor=black)

<br>

### ERD
<img width="902" height="845" alt="image" src="https://github.com/user-attachments/assets/ecb3844b-ef76-4a23-b8a9-208b8e3e21a8" />

<br>

### 🏗️ System Architecture
<img width="700" height="624" alt="image" src="https://github.com/user-attachments/assets/ea053544-48eb-44b2-ad93-d34edc8b4e12" />
