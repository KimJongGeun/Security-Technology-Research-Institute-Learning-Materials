# Web Attack 시리즈 — 진행 상태와 다음 작업

## 현재까지 작성된 챕터

- 01. HTTP 요청 해부
- 02. OWASP Top 10:2025 × WAF 커버리지 매트릭스
- 03. WAF 기초 — 동작 원리와 룰 설계
- 04. SQL Injection
- 05. XSS (Reflected / Stored / DOM)
- 06. Command Injection & SSRF
- 07. Path Traversal & File Inclusion

## 다음 작업 예정 (우선순위 순)

### 08. 인증·세션 취약점
- 크리덴셜 스터핑 방어 (Exposed Credentials Check + Rate Limiting + Turnstile)
- 세션 고정·탈취, JWT 검증 함정
- MFA bypass 패턴
- OAuth/OIDC 오용

### 09. 공개 CVE 시그니처 설계
- Log4Shell (`${jndi:ldap://...}`)
- Spring4Shell (`class.module.classLoader`)
- Struts OGNL (`%{...}`)
- 제로데이 발표 시 48시간 내 임시 룰 배포 프로세스

### 10. 봇 방어 심화
- JA3 / JA4 TLS fingerprint 실전
- Bot Score 임계값 튜닝
- Turnstile / Managed Challenge / Interactive Challenge 사용처 분리
- 스크래퍼·크리덴셜 스터핑·카드 테스터 분류

### 11. Logpush → SIEM 파이프라인
- Cloudflare Logpush HTTP requests / Firewall events 필드
- R2·S3·Splunk HEC·ELK 적재 흐름
- 핵심 경보(Attack Score 급락, 신규 국가 유입, 4xx 급증) 설계

### 12. API 보안
- OWASP API Top 10 2023 매핑
- API Shield 스키마 검증 / JWT 검증 / Sequence Mitigation
- BOLA / BFLA 탐지 한계

### 13. HTTP Request Smuggling
- CL.TE / TE.CL / TE.TE
- HTTP/2 downgrade smuggling
- Cloudflare 단에서의 탐지 한계와 오리진 설정

---

## 원칙

- 각 챕터는 단독으로 읽을 수 있게 작성
- 공식 문서·RFC·OWASP 원문만 참조 링크로 사용
- 예시 도메인·IP는 RFC 예약 대역(`example.com`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)만 사용
- Cloudflare 룰 표현식은 실제 wirefilter 문법으로 작성 (`contains`, `matches`, `lt` 등)
