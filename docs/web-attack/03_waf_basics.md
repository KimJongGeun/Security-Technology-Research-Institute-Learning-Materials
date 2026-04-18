# 03. WAF 기초 — 동작 원리와 룰 설계

## 학습 목표
- WAF가 요청을 검사하는 전체 흐름을 단계별로 설명할 수 있다
- Cloudflare의 Phase/Action 개념과 Managed vs Custom Rule의 위치를 이해한다
- 룰 하나를 설계할 때 고려해야 할 변수(정확도, 성능, 오탐)를 체크리스트로 안다

---

## 1. WAF의 본질 — 요청 검사기 + 판정기

WAF는 다음 두 가지를 한다.

1. **검사(Inspection)** — 요청의 필드(URI, 헤더, 바디, 쿠키 등)를 파싱해서 패턴이나 점수를 뽑는다
2. **판정(Action)** — 결과에 따라 Allow / Challenge / Block 등의 처리를 한다

Cloudflare의 Ruleset Engine은 이 두 단계를 **wirefilter 표현식 + Action** 쌍으로 모델링한다.

```
표현식: http.request.uri.path contains "/admin" and ip.src.country ne "KR"
Action: Managed Challenge
```

---

## 2. Cloudflare 요청 처리 Phase (단순화)

Cloudflare는 요청을 여러 단계로 처리한다. 개념을 단순화하면 다음 순서다.

```
[클라이언트]
    ↓
[1] L3/L4 DDoS 방어 (네트워크)
    ↓
[2] TLS 종료 + JA3/JA4 fingerprint 수집
    ↓
[3] Bot Management (봇 점수 산출)
    ↓
[4] WAF Custom Rules (사용자가 만든 룰)
    ↓
[5] WAF Managed Rules (Cloudflare/OWASP 룰)
    ↓
[6] Rate Limiting Rules
    ↓
[7] 캐시 조회 / Origin 전달
    ↓
[오리진 서버]
```

### 중요 포인트
- **Custom Rule이 Managed Rule보다 먼저 평가**되는 단계가 있어서 Skip/Allow를 커스텀에서 명시적으로 제어할 수 있다
- 실제 Phase 구조는 더 복잡하며 공식 문서의 Phase 다이어그램을 참고할 것
- 각 Phase의 룰은 독립된 Ruleset으로 관리되므로 우선순위와 상호작용에 주의

> Cloudflare 공식 문서: https://developers.cloudflare.com/ruleset-engine/about/phases/

---

## 3. Managed Rules vs Custom Rules

### Managed Rules
- Cloudflare가 관리하는 시그니처 기반 룰 묶음
- **Cloudflare Managed Ruleset**: 광범위한 공격 시그니처 (CVE 포함)
- **Cloudflare OWASP Core Ruleset**: ModSecurity OWASP CRS 포팅
- **Cloudflare Exposed Credentials Check**: 유출 계정 차단
- **Cloudflare Sensitive Data Detection**: 응답 PII 탐지

장점:
- 운영 부담 낮음
- 신규 CVE에 대해 Cloudflare가 빠르게 룰 추가

단점:
- 우리 조직 특수 경로/로직은 커버 불가
- 오탐 시 개별 룰 Skip 필요

### Custom Rules
- 조직이 직접 작성하는 wirefilter 표현식
- Managed가 놓치는 영역 또는 비즈니스 고유 패턴 차단
- Skip / Log / Challenge / Block / JS Challenge / Interactive Challenge 등 Action 선택

장점:
- 정밀 제어
- 우리 서비스 트래픽 특성에 맞춤

단점:
- 유지보수 비용 발생
- 잘못 짜면 전면 장애 유발 가능

---

## 4. Action 종류

| Action | 동작 | 사용 시점 |
|---|---|---|
| **Allow** | 이후 WAF 평가 스킵 | 신뢰 트래픽 화이트리스트 |
| **Log** | 로깅만, 차단 없음 | 룰 배포 초기 오탐 관찰 |
| **Skip** | 지정한 룰/Phase 건너뛰기 | 특정 Managed 룰 예외 |
| **Managed Challenge** | Cloudflare가 적응적 Challenge | 의심스러운데 확실하지 않을 때 |
| **JS Challenge** | 자바스크립트 기반 Challenge | 봇 의심 |
| **Interactive Challenge** | 사용자 상호작용 필요 | 강한 의심 |
| **Block** | 403 응답 | 명백한 공격 |

### 실무 권장 흐름
```
새 룰 배포 → Log (1~3일 관찰) → Managed Challenge (오탐 추가 관찰) → Block
```

처음부터 Block으로 배포하면 정상 트래픽 차단 사고가 발생한다.

---

## 5. 민감도(Sensitivity) 개념

Cloudflare Managed Ruleset에는 **Sensitivity(민감도)** 설정이 있다. (기존 ModSecurity의 paranoia level과 유사한 개념)

| Sensitivity | 특성 | 권장 환경 |
|---|---|---|
| Low | 고신뢰 패턴만 차단, 오탐 적음 | 초기 도입, 정상 트래픽 다양 |
| Medium | 균형 | **기본 추천값** |
| High | 더 공격적 탐지, 오탐 증가 | 관리 경로, 내부 시스템 |

동일 Ruleset을 경로별로 다르게 걸 수 있다. 예: `/api/*` 는 High, `/public/*` 는 Medium.

> 공식 문서(민감도·Action 조정): https://developers.cloudflare.com/waf/managed-rules/

---

## 6. wirefilter 표현식 기본 문법

### 비교 연산자
| 연산자 | 의미 |
|---|---|
| `eq`, `ne` | 같음/다름 |
| `contains` | 부분 문자열 포함 |
| `matches` | 정규식 매칭 |
| `in { ... }` | 집합 포함 |
| `and`, `or`, `not` | 논리 연산 |

### 예시
```
# 특정 경로에 대한 관리자 IP 허용
(http.request.uri.path matches "^/admin") and
(ip.src in {192.0.2.1 192.0.2.2})

# 의심스러운 UA 차단
(http.user_agent contains "sqlmap") or
(http.user_agent contains "nikto") or
(http.user_agent contains "nuclei")

# 국가 + 봇 점수 조합
(ip.src.country in {"RU" "KP"}) and
(cf.bot_management.score < 30)

# SQLi 점수 기반 탐지
(cf.waf.score.sqli < 20)
```

### 변환 함수
`lower()`, `url_decode()`, `len()`, `regex_replace()` 등. 자세한 레퍼런스는 공식 문서 참조.

> 함수 레퍼런스: https://developers.cloudflare.com/ruleset-engine/rules-language/functions/

---

## 7. 룰 하나 설계할 때 고려할 5가지

### 7.1 정확도 (Accuracy)
- 정상 트래픽에 걸리지 않는가?
- 공격 변형(인코딩·대소문자·우회)에도 걸리는가?
- 검증: 과거 로그 대비 오탐/탐지율 시뮬레이션

### 7.2 우회 저항성
- URL 인코딩·이중 인코딩으로 우회 가능한가?
- Content-Type 변경으로 우회 가능한가?
- 대소문자·공백·주석 삽입으로 우회 가능한가?
- → 반드시 `lower(url_decode(...))` 정규화 후 매칭

### 7.3 성능
- 과도하게 무거운 정규식은 지연 발생
- 복잡한 중첩 함수는 가능하면 필드별로 분리

### 7.4 유지보수성
- 룰 이름에 목적 명시 (`block_sqli_on_api_v2_login`)
- 설명 필드에 근거·CVE·티켓 번호 남기기
- 임시 룰은 만료일을 설명에 기록

### 7.5 로깅
- Log 모드 구간 필수
- Logpush 연동으로 SIEM에 적재
- 이벤트 급증 시 알림 연동

---

## 8. 예시 — 로그인 경로 보호 룰 세트

실제 설계할 법한 룰 세트를 단계별로 본다.

### 8.1 관리자 경로 제한
```
(http.request.uri.path matches "^/admin") and
(not ip.src in $internal_ips)
→ Block
```
`$internal_ips`는 Cloudflare IP List 기능으로 관리.

### 8.2 로그인 레이트 리밋 (Rate Limiting Rules)
```
경로: /api/login
기준: ip.src 당 1분에 10회 초과 POST
Action: Block 10분
```

### 8.3 자동화 도구 차단
```
(lower(http.user_agent) contains "sqlmap" or
 lower(http.user_agent) contains "nikto" or
 lower(http.user_agent) contains "nuclei" or
 lower(http.user_agent) contains "ffuf")
→ Block
```

### 8.4 SQLi 점수 기반 탐지
```
(http.request.uri.path matches "^/api/") and
(cf.waf.score.sqli < 20)
→ Managed Challenge
```

### 8.5 비정상 Content-Type 차단
```
(http.request.uri.path matches "^/api/") and
(http.request.method in {"POST" "PUT" "PATCH"}) and
(not any(http.request.headers["content-type"][*] in
  {"application/json" "application/x-www-form-urlencoded"}))
→ Block
```

---

## 9. 체크포인트

<details>
<summary>Q1. 새 룰을 처음부터 Block으로 배포하면 왜 위험한가?</summary>

정상 트래픽이 예상과 다르게 룰에 걸릴 수 있다. Log 모드로 최소 수일 관찰하여 오탐률을 측정하고, Managed Challenge를 거쳐 Block으로 올리는 단계가 필요하다. 바로 Block하면 서비스 장애로 이어질 수 있다.
</details>

<details>
<summary>Q2. `http.user_agent contains "sqlmap"` 만으로 자동화 도구를 차단할 수 있을까?</summary>

부족하다. (1) UA는 언제든 위조 가능. (2) 대소문자 변형에 약하므로 `lower(http.user_agent)`로 정규화 필요. (3) UA 외에도 JA3/JA4 fingerprint, 요청 속도, 쿠키 사용 여부 등 행동 기반 신호와 결합해야 한다.
</details>

<details>
<summary>Q3. Custom Rule에서 특정 Managed 룰 하나만 예외 처리하려면?</summary>

해당 Managed Ruleset 또는 특정 Rule ID에 대해 **Skip** Action을 사용한다. 조건에 경로·IP·UA 등을 명시하여 예외 범위를 최소화한다. 전체 Managed Ruleset을 Skip하면 방어가 무력화되므로 룰 ID 단위로 예외를 둔다.
</details>

---

## 10. 더 읽을거리

- Cloudflare Ruleset Engine 개요: https://developers.cloudflare.com/ruleset-engine/
- Phases: https://developers.cloudflare.com/ruleset-engine/about/phases/
- Rules language 문법: https://developers.cloudflare.com/ruleset-engine/rules-language/
- 함수 레퍼런스: https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
- Custom Rules: https://developers.cloudflare.com/waf/custom-rules/
- Managed Rules: https://developers.cloudflare.com/waf/managed-rules/
- Rate Limiting Rules: https://developers.cloudflare.com/waf/rate-limiting-rules/

---

**다음 챕터**: `04_injection_sqli.md` — SQL Injection 패턴, 우회 기법, Cloudflare 룰 설계 (작성 예정)
