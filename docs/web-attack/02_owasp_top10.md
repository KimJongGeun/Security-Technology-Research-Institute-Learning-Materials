# 02. OWASP Top 10 × WAF 커버리지 매트릭스

## 학습 목표
- OWASP Top 10 각 항목의 본질을 한 줄로 설명할 수 있다
- 어떤 항목이 WAF로 커버되고, 어떤 것이 애플리케이션 로직에서만 막을 수 있는지 구분한다
- Cloudflare Managed Ruleset이 커버하는 범위와 Custom Rule을 써야 하는 영역을 안다

---

## 1. OWASP Top 10 (현재 릴리스 기준)

현재 공식 릴리스는 **OWASP Top 10:2021** 이며, 2025년 기준 차기 버전이 준비 중이다. 이 문서는 2021 안정판을 기준으로 정리한다.

### 10대 항목

| # | 코드 | 이름 | 핵심 |
|---|---|---|---|
| 1 | A01 | **Broken Access Control** | 인가(Authorization) 실패. IDOR, 경로 건너뛰기 |
| 2 | A02 | **Cryptographic Failures** | 민감 데이터 평문 저장/전송, 약한 암호 |
| 3 | A03 | **Injection** | SQLi/NoSQLi/OS command/LDAP/XPath/SSTI 포함 |
| 4 | A04 | **Insecure Design** | 설계 단계 결함 (레이트 리밋 부재, 워크플로우 취약) |
| 5 | A05 | **Security Misconfiguration** | 디폴트 계정, 불필요 기능 활성, S3 버킷 오픈 |
| 6 | A06 | **Vulnerable and Outdated Components** | 알려진 CVE 있는 라이브러리 |
| 7 | A07 | **Identification and Authentication Failures** | 세션/MFA/크리덴셜 스터핑 |
| 8 | A08 | **Software and Data Integrity Failures** | 공급망, 서명 검증 부재, deserialization |
| 9 | A09 | **Security Logging and Monitoring Failures** | 로깅/탐지 체계 부재 |
| 10 | A10 | **Server-Side Request Forgery (SSRF)** | 서버가 공격자 제어 URL로 요청 |

### 별도 참고 자료
- **OWASP API Security Top 10 2023** — API 관점의 별도 순위 (BOLA, BFLA 등)
- **OWASP Top 10 for LLM Applications** — LLM 통합 앱의 프롬프트 인젝션 등

---

## 2. WAF 커버리지 매트릭스

각 항목이 **WAF 레이어에서 얼마나 막을 수 있는지**를 실무 관점으로 정리한다.

| 항목 | WAF 차단 가능성 | 설명 |
|---|---|---|
| A01 Broken Access Control | 부분 | 경로 패턴/레이트 리밋은 가능. 인가 로직은 앱에서 |
| A02 Cryptographic Failures | 거의 불가 | TLS 강제, HSTS 헤더 주입은 가능 |
| A03 Injection | 강함 | SQLi/XSS/RCE 패턴 매칭 — WAF의 주전장 |
| A04 Insecure Design | 부분 | 레이트 리밋, 봇 방어로 완화 |
| A05 Misconfiguration | 부분 | 관리 경로 차단, 기본 에러 페이지 마스킹 |
| A06 Vulnerable Components | 강함 | 알려진 CVE 시그니처(Log4Shell, Spring4Shell 등) |
| A07 Auth Failures | 부분 | 크리덴셜 스터핑 레이트 리밋, Bot Score |
| A08 Integrity Failures | 거의 불가 | deserialization 페이로드 일부는 탐지 가능 |
| A09 Logging Failures | 보조 | WAF 자체가 로그 소스 |
| A10 SSRF | 부분 | 메타데이터 URL(169.254.169.254) 패턴은 차단 가능 |

**핵심 통찰**: WAF는 **Injection·Known CVE·Rate-based 공격**에 강하고, **인가/설계/암호화**는 애플리케이션 책임이다. WAF에 모든 걸 맡기면 반드시 뚫린다.

---

## 3. Cloudflare 기본 제공 vs 커스텀 영역

### 3.1 Managed Rulesets (기본 제공)
Cloudflare가 관리하는 룰 묶음. 켜기만 하면 적용된다.

| Ruleset | 대상 | Top 10 매핑 |
|---|---|---|
| **Cloudflare Managed Ruleset** | 일반 웹 공격 전반 | A03 (Injection), A06 (CVE) |
| **Cloudflare OWASP Core Ruleset** | ModSecurity CRS 포팅 | A03 중심 (paranoia level 조절) |
| **Cloudflare Exposed Credentials Check** | 알려진 유출 계정 차단 시도 | A07 |
| **Cloudflare Sensitive Data Detection** | 응답 바디에서 PII 유출 탐지 | A02 (보조) |
| **API Shield** | 스키마 기반 검증 | A01, A03 (API 관점) |
| **Bot Management / Super Bot Fight Mode** | 봇 점수/JA4 | A04, A07 |
| **Rate Limiting** | 임계 기반 | A04, A07 |

### 3.2 Custom Rules가 필요한 경우
Managed로 못 잡는 케이스:
- 우리 조직 고유 경로/파라미터 기반 공격 (특정 비즈니스 엔드포인트에 대한 특수 페이로드)
- False Positive가 심한 Managed 룰을 skip하되 특정 패턴만 막고 싶을 때
- GeoIP + 특정 UA 조합 같은 복합 조건
- JA4 fingerprint 기반 악성 봇 군집 차단
- 새 CVE가 떠서 Managed 룰 업데이트 전에 긴급 패치

### 3.3 Rate Limiting & Bot — 별도 엔진
- **Rate Limiting Rules**: 경로별/국가별/세션별 속도 제한. A04/A07 방어의 중핵
- **Super Bot Fight Mode / Bot Management**: A04, A07 보조. JA3/JA4 + 행동 분석

---

## 4. 각 항목별 대표 공격과 WAF 대응 요약

이후 챕터에서 상세 다루지만, 개요만 잡아둔다.

### A03 Injection
- SQLi → `cf.waf.score.sqli` + 커스텀 키워드 룰
- XSS → `cf.waf.score.xss` + 태그/이벤트 패턴
- Command Injection → 셸 메타 문자 + base64 디코드 검사
- SSTI (`{{7*7}}`, `${...}`) → 표현식 구문 매칭

### A06 Vulnerable Components
- Log4Shell: `${jndi:ldap://...}` 패턴
- Spring4Shell: `class.module.classLoader` 패턴
- Struts: `%{...}` OGNL
- Cloudflare Managed가 대부분 커버하지만 **제로데이 시점**엔 커스텀 룰 필요

### A07 Auth Failures
- 크리덴셜 스터핑: 짧은 시간에 다양한 계정 로그인 시도
- **대응**: 경로별 레이트 리밋 + Bot Score + Turnstile

### A10 SSRF
- 타겟 URL: `169.254.169.254` (AWS IMDS), `metadata.google.internal`, `localhost`
- **Cloudflare에선** 아웃바운드가 아니라 인바운드 요청의 파라미터에서 탐지

---

## 5. 실무 체크리스트 (Cloudflare 기준)

### 5.1 "일단 켜야 할" 것
- [ ] Cloudflare Managed Ruleset — 민감도(Sensitivity)는 **Medium**부터 시작
- [ ] Cloudflare OWASP Core Ruleset — 처음엔 Log only, 1~2주 관찰 후 Block 전환
- [ ] Super Bot Fight Mode 또는 Bot Management (유료)
- [ ] Rate Limiting Rules — 민감 경로(로그인, OTP, 출금 등) 우선
- [ ] Exposed Credentials Check
- [ ] TLS 1.2+ 강제, HSTS 헤더 주입

### 5.2 환경별 커스텀 룰 기본 세트
- [ ] 관리자 경로(`/admin`, `/internal`) — 사내 IP/VPN만 허용
- [ ] `.git`, `.env`, `config.json` 등 민감 파일 접근 차단
- [ ] 비정상 Content-Type (API 경로에 `text/plain` 등) 차단
- [ ] 고위험 국가(GeoIP) 대상 Challenge
- [ ] 자동화 툴 UA (`sqlmap`, `nikto`, `nuclei`, `ffuf`) 즉시 Block

### 5.3 지속 운영 항목
- [ ] WAF 이벤트를 Logpush로 SIEM(Splunk/ELK) 전송
- [ ] 주간 False Positive 리뷰
- [ ] 신규 CVE 관측 시 48시간 내 임시 룰 작성
- [ ] 분기별 민감도(Sensitivity) 상향 검토

---

## 6. 체크포인트

<details>
<summary>Q1. Cloudflare Managed Ruleset만 켜면 OWASP Top 10 중 몇 개를 완전히 커버하는가?</summary>

**거의 없다**. Managed는 A03(Injection)과 A06(Known CVE)을 잘 커버하지만, A01(인가), A02(암호), A04(설계), A07(인증), A08(무결성)은 **애플리케이션 레벨 책임**이다. WAF는 방어심층의 한 겹일 뿐.
</details>

<details>
<summary>Q2. SSRF(A10)를 WAF에서 막는다면 어떤 필드를 검사해야 하는가?</summary>

**인바운드** 요청의 **사용자 입력 파라미터**에서 URL 형태의 값을 검사. 대표적으로 `169.254.169.254`, `metadata.google.internal`, `localhost`, `127.0.0.1`, `0.0.0.0`, `[::]` 등 내부 메타데이터/루프백 주소가 query/body에 포함되었는지.

단, 진짜 SSRF 방어는 **서버 측 outbound 제어**(VPC 수준 차단, IMDSv2 강제, deny list)가 정석. WAF는 보조.
</details>

<details>
<summary>Q3. 새 CVE가 발표됐다. 48시간 내 WAF에서 취할 수 있는 조치 순서?</summary>

1. **PoC 분석** — 어떤 경로/파라미터/페이로드 패턴인지 파악
2. **Log 모드 룰 배포** — 패턴 기반 탐지 룰을 Log only로 올려 현황 관찰
3. **오탐 리뷰** — 정상 트래픽에 걸리는지 1~3시간 체크
4. **Challenge / Block 전환** — 오탐 없으면 Managed Challenge 또는 Block
5. **SIEM 알림** — 동일 패턴 급증 시 경보
6. **Cloudflare Managed Ruleset 업데이트 모니터링** — 공식 룰 추가되면 커스텀 룰 철회
</details>

---

## 7. 더 읽을거리

- OWASP Top 10:2021 공식: https://owasp.org/Top10/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Cloudflare Managed Rulesets: https://developers.cloudflare.com/waf/managed-rules/
- Cloudflare OWASP Core Ruleset: https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/
- Cloudflare Rate Limiting Rules: https://developers.cloudflare.com/waf/rate-limiting-rules/

---

**다음 챕터**: `03_waf_basics.md` — WAF 동작 원리, Managed vs Custom, 민감도(Sensitivity), Action 흐름
