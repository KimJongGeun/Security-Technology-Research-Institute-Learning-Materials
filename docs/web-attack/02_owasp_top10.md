# 02. OWASP Top 10:2025 × WAF 커버리지 매트릭스

## 학습 목표
- OWASP Top 10:2025 각 항목의 본질을 한 줄로 설명할 수 있다
- 어떤 항목이 WAF로 커버되고, 어떤 것이 애플리케이션 로직에서만 막을 수 있는지 구분한다
- Cloudflare Managed Ruleset이 커버하는 범위와 Custom Rule을 써야 하는 영역을 안다

---

## 1. OWASP Top 10:2025 개요

2026년 4월 시점의 최신 공식 버전은 **OWASP Top 10:2025**이다. 2021 대비 신규 항목 2개(공급망, 예외 처리)가 추가되고 순위가 크게 재편되었다.

> 공식 페이지: https://owasp.org/Top10/2025/

### 10대 항목

| # | 코드 | 이름 | 핵심 |
|---|---|---|---|
| 1 | A01:2025 | **Broken Access Control** | 인가(Authorization) 실패. IDOR, 경로 건너뛰기 |
| 2 | A02:2025 | **Security Misconfiguration** | 디폴트 계정, 불필요 기능 활성, 잘못된 권한 |
| 3 | A03:2025 | **Software Supply Chain Failures** | 의존성·빌드·배포 체인 전반 (2021의 Vulnerable Components 확장) |
| 4 | A04:2025 | **Cryptographic Failures** | 민감 데이터 평문 저장/전송, 약한 암호 |
| 5 | A05:2025 | **Injection** | SQLi/NoSQLi/OS command/LDAP/XPath/SSTI 포함 |
| 6 | A06:2025 | **Insecure Design** | 설계 단계 결함 (레이트 리밋 부재, 워크플로우 취약) |
| 7 | A07:2025 | **Authentication Failures** | 세션/MFA/크리덴셜 스터핑 |
| 8 | A08:2025 | **Software or Data Integrity Failures** | 서명 검증 부재, deserialization |
| 9 | A09:2025 | **Security Logging and Alerting Failures** | 로깅·탐지·경보 체계 부재 |
| 10 | A10:2025 | **Mishandling of Exceptional Conditions** | 예외/에러 처리 결함 (신규) |

### 2021 → 2025 주요 변화
- **신규**: A03(Supply Chain), A10(Exceptional Conditions)
- **순위 급상승**: Security Misconfiguration (5→2)
- **순위 하락**: Cryptographic Failures (2→4), Injection (3→5), Insecure Design (4→6)
- **이름 변경**: "Identification and Authentication Failures" → "Authentication Failures", "Logging and Monitoring" → "Logging and Alerting"
- **A10 SSRF 제거**: 2025에서는 별도 항목이 아닌 다른 카테고리로 흡수. SSRF 자체의 중요성은 여전하지만 Top 10 단독 항목에서는 빠짐

### 관련 표준
- **OWASP API Security Top 10 2023** — API 관점 (BOLA, BFLA 등). 2026-04 시점 최신.
- **OWASP Top 10 for LLM Applications 2025** — LLM 통합 앱. 2024-11 공개, 2026-04 시점 최신.
- **OWASP Top 10 for Agentic Applications 2026** — 에이전트/도구호출 시스템. 2026년판 공개.

---

## 2. WAF 커버리지 매트릭스

각 항목이 **WAF 레이어에서 얼마나 막을 수 있는지**를 실무 관점으로 정리한다.

| 항목 | WAF 차단 가능성 | 설명 |
|---|---|---|
| A01 Broken Access Control | 부분 | 경로 패턴/레이트 리밋은 가능. 인가 로직은 앱에서 |
| A02 Security Misconfiguration | 부분 | 관리 경로 차단, 기본 에러 페이지 마스킹, 메서드 제한 |
| A03 Software Supply Chain Failures | 거의 불가 | 런타임 트래픽이 아니라 빌드·배포 영역. WAF 기여는 CVE 시그니처에 국한 |
| A04 Cryptographic Failures | 거의 불가 | TLS 강제, HSTS 헤더 주입은 가능 |
| A05 Injection | 강함 | SQLi/XSS/RCE 패턴 매칭 — WAF의 주전장 |
| A06 Insecure Design | 부분 | 레이트 리밋, 봇 방어로 완화 |
| A07 Authentication Failures | 부분 | 크리덴셜 스터핑 레이트 리밋, Bot Score |
| A08 Integrity Failures | 거의 불가 | deserialization 페이로드 일부는 탐지 가능 |
| A09 Logging/Alerting | 보조 | WAF 자체가 로그 소스 |
| A10 Exceptional Conditions | 거의 불가 | 앱 내부 예외 처리 영역 |

**핵심 통찰**: WAF는 **Injection·Known CVE·Rate-based 공격**에 강하고, **인가/설계/암호화/공급망/예외 처리**는 애플리케이션·빌드 파이프라인 책임이다. WAF에 모든 걸 맡기면 반드시 뚫린다.

---

## 3. Cloudflare 기본 제공 vs 커스텀 영역

### 3.1 Managed Rulesets (기본 제공)
Cloudflare가 관리하는 룰 묶음. 켜기만 하면 적용된다.

| Ruleset | 대상 | Top 10:2025 매핑 |
|---|---|---|
| **Cloudflare Managed Ruleset** | 일반 웹 공격 전반 | A05 (Injection), A03 (CVE 시그니처) |
| **Cloudflare OWASP Core Ruleset** | ModSecurity CRS 포팅 | A05 중심 (민감도 조절) |
| **Cloudflare Exposed Credentials Check** | 알려진 유출 계정 차단 시도 | A07 |
| **Cloudflare Sensitive Data Detection** | 응답 바디에서 PII 유출 탐지 | A04 (보조) |
| **API Shield** | 스키마 기반 검증 | A01, A05 (API 관점) |
| **Bot Management / Super Bot Fight Mode** | 봇 점수/JA4 | A06, A07 |
| **Rate Limiting Rules** | 임계 기반 | A06, A07 |

### 3.2 Custom Rules가 필요한 경우
Managed로 못 잡는 케이스:
- 조직 고유 경로/파라미터 기반 공격
- False Positive가 심한 Managed 룰을 Skip하되 특정 패턴만 막고 싶을 때
- GeoIP + 특정 UA 조합 같은 복합 조건
- JA4 fingerprint 기반 악성 봇 군집 차단
- 새 CVE가 떠서 Managed 룰 업데이트 전에 긴급 패치

### 3.3 Rate Limiting & Bot — 별도 엔진
- **Rate Limiting Rules**: 경로별/국가별/세션별 속도 제한. A06/A07 방어의 중핵
- **Super Bot Fight Mode / Bot Management**: A06, A07 보조. JA3/JA4 + 행동 분석

---

## 4. 각 항목별 대표 공격과 WAF 대응 요약

### A05 Injection
- SQLi → `cf.waf.score.sqli` + 커스텀 키워드 룰
- XSS → `cf.waf.score.xss` + 태그/이벤트 패턴
- Command Injection → 셸 메타 문자 + base64 디코드 검사
- SSTI (`{{7*7}}`, `${...}`) → 표현식 구문 매칭

### A03 Supply Chain Failures
- Log4Shell: `${jndi:ldap://...}` 패턴
- Spring4Shell: `class.module.classLoader` 패턴
- Struts: `%{...}` OGNL
- Cloudflare Managed가 대부분 커버하지만 **제로데이 시점**엔 커스텀 룰 필요
- 단, 공급망 리스크 본체(빌드 서명·SBOM·아티팩트 무결성)는 WAF 범위 밖. Sigstore/SLSA/SBOM 정책과 함께 간다.

### A07 Authentication Failures
- 크리덴셜 스터핑: 짧은 시간에 다양한 계정 로그인 시도
- **대응**: 경로별 레이트 리밋 + Bot Score + Turnstile + Exposed Credentials Check

### A02 Security Misconfiguration (순위 급상승 이유)
- 클라우드 오픈 버킷, 기본 계정, 과도한 권한, 관리 콘솔 노출
- WAF에서 할 수 있는 일: 관리 경로 IP 제한, 비허용 메서드 차단, 디렉터리 인덱싱 경로 차단

### SSRF (2025에서 단독 항목 아님)
- 타겟 URL: `169.254.169.254` (AWS IMDS), `metadata.google.internal`, `localhost`
- **Cloudflare에선** 아웃바운드가 아니라 인바운드 요청 파라미터에서 URL 형태 값을 검사

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
<summary>Q1. Cloudflare Managed Ruleset만 켜면 OWASP Top 10:2025 중 몇 개를 완전히 커버하는가?</summary>

**거의 없다**. Managed는 A05(Injection)와 A03의 알려진 CVE 일부를 잘 커버하지만, A01(인가), A02(설정), A04(암호), A06(설계), A07(인증), A08(무결성), A10(예외)는 **애플리케이션 레벨 책임**이다. WAF는 방어심층의 한 겹일 뿐.
</details>

<details>
<summary>Q2. SSRF가 2025에서 Top 10 단독 항목이 아닌데, 그럼 무시해도 되는가?</summary>

아니다. SSRF는 **중요도가 낮아진 것이 아니라** 다른 카테고리로 흡수·재분류된 것이다. 클라우드 메타데이터 탈취는 여전히 치명적이므로 인바운드 파라미터에서 `169.254.169.254`, `metadata.google.internal`, `localhost`, `127.0.0.1`, `[::]` 등 내부 주소 탐지와 **서버 측 outbound 제어**(VPC 차단, IMDSv2 강제)를 병행해야 한다.
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

- OWASP Top 10:2025 공식: https://owasp.org/Top10/2025/
- OWASP Top 10 Introduction: https://owasp.org/Top10/2025/0x00_2025-Introduction/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Cloudflare Managed Rulesets: https://developers.cloudflare.com/waf/managed-rules/
- Cloudflare OWASP Core Ruleset: https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/
- Cloudflare Rate Limiting Rules: https://developers.cloudflare.com/waf/rate-limiting-rules/

---

**다음 챕터**: `03_waf_basics.md` — WAF 동작 원리, Managed vs Custom, 민감도(Sensitivity), Action 흐름
