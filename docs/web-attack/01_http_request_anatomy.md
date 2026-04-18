# 01. HTTP 요청 해부 — WAF가 보는 시점

## 학습 목표
- HTTP 요청의 구성 요소를 분해하고, 각 필드가 어떤 공격 벡터가 되는지 설명할 수 있다
- Cloudflare Ruleset Engine의 필드 이름과 실제 HTTP 구조를 1:1로 매핑할 수 있다
- 로그에서 요청 한 줄을 보고 어느 필드에 룰을 걸어야 하는지 판단할 수 있다

---

## 1. HTTP 요청의 구조

실제 요청 한 건을 분해해본다.

```http
POST /api/login?redirect=%2Fdashboard HTTP/1.1
Host: api.example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
Accept: application/json
Content-Type: application/json
Cookie: session=abc123; csrf=xyz789
X-Forwarded-For: 203.0.113.45
Content-Length: 52

{"email":"user@example.com","password":"p@ssw0rd"}
```

> 예시 주소는 모두 RFC 2606(`example.com`)과 RFC 5737(`203.0.113.0/24`) 예약 대역을 사용했다.

### 구성 요소 분해

| 구분 | 내용 | 공격 표면 예시 |
|---|---|---|
| Method | `POST` | HTTP verb tampering |
| Path | `/api/login` | Path traversal, LFI, 라우트 스캐닝 |
| Query String | `?redirect=%2Fdashboard` | Open redirect, XSS, SQLi |
| HTTP Version | `HTTP/1.1` | HTTP/2 downgrade 관련 smuggling |
| Host | `api.example.com` | Host header injection, routing bypass |
| User-Agent | Mozilla/... | UA 스푸핑, 봇 탐지 우회 |
| Cookie | `session=...` | 세션 하이재킹, CSRF |
| X-Forwarded-For | `203.0.113.45` | **클라이언트가 제어 가능** → IP 위조 |
| Content-Type | `application/json` | 파싱 엔진 차이로 WAF 우회 |
| Body | `{"email":"..."}` | SQLi/XSS/RCE/Deserialization |

핵심: **클라이언트가 제어 가능한 필드는 전부 공격 페이로드 투입점**이다. Host, User-Agent, Cookie, XFF, Referer까지 포함된다.

---

## 2. Cloudflare Ruleset Engine이 보는 필드

Cloudflare는 wirefilter 언어로 요청을 검사한다. 자주 쓰는 필드 정리.

> 출처: [Cloudflare Rules language fields reference](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/)

### 2.1 요청 라인
| 필드 | 의미 |
|---|---|
| `http.request.method` | GET/POST/PUT/DELETE... |
| `http.request.uri` | `/api/login?redirect=%2Fdashboard` (경로+쿼리) |
| `http.request.uri.path` | `/api/login` |
| `http.request.uri.query` | `redirect=%2Fdashboard` |
| `http.request.full_uri` | `https://api.example.com/api/login?...` |
| `http.request.version` | `HTTP/1.1`, `HTTP/2`, `HTTP/3` |

### 2.2 헤더
| 필드 | 의미 |
|---|---|
| `http.host` | Host 헤더 값 |
| `http.user_agent` | User-Agent |
| `http.referer` | Referer |
| `http.request.headers` | 헤더 map (키/값 전체) |
| `http.request.headers.names` | 헤더 이름 배열 |
| `http.request.headers.values` | 헤더 값 배열 |
| `http.request.cookies` | 쿠키 map |

### 2.3 바디
| 필드 | 의미 | 비고 |
|---|---|---|
| `http.request.body.raw` | 요청 바디 전체 (문자열) | 유료 플랜 제약 있음. 공식 문서 확인 권장 |
| `http.request.body.size` | 바이트 크기 | |
| `http.request.body.truncated` | 바디가 잘렸는지 | 큰 요청 우회 주의 |
| `http.request.body.form` | `application/x-www-form-urlencoded` 파싱 결과 | |
| `http.request.body.form.names` | 폼 필드 이름 배열 | |
| `http.request.body.form.values` | 폼 필드 값 배열 | |
| `http.request.body.mime` | 실제 파싱된 MIME 타입 | |

### 2.4 클라이언트 / 네트워크
| 필드 | 의미 |
|---|---|
| `ip.src` | TCP 레벨 실제 클라이언트 IP (Cloudflare가 본 값, 신뢰 가능) |
| `ip.src.country` | ISO 국가 코드 |
| `ip.src.asnum` | ASN |
| `cf.client.bot` | Cloudflare 판정 봇 여부 |
| `cf.bot_management.score` | 1~99 (낮을수록 봇 의심). Bot Management add-on 필요 |
| `cf.bot_management.verified_bot` | Googlebot 등 검증된 봇 여부 |
| `cf.bot_management.ja3_hash` | JA3 TLS fingerprint |
| `cf.bot_management.ja4` | JA4 fingerprint |
| `cf.threat_score` | 0~100 (높을수록 위협 의심) |
| `cf.waf.score.sqli` | SQLi attack score |
| `cf.waf.score.xss` | XSS attack score |
| `cf.waf.score.rce` | RCE attack score |
| `cf.waf.score` | 종합 attack score |

### WAF Attack Score 해석 (중요)
> 출처: [Cloudflare WAF attack score](https://developers.cloudflare.com/waf/about/waf-attack-score/)

- 범위: **1 ~ 99** (특수값 100 존재)
- 방향: **1에 가까울수록 악성 가능성 높음, 99에 가까울수록 정상**
- 룰은 보통 `cf.waf.score.sqli < 20` 같은 형태로 건다
- Enterprise 플랜에서 사용 가능

---

## 3. 클라이언트 제어 필드 vs 서버 판정 필드

공격 탐지 설계에서 가장 중요한 구분이다.

### 🔴 클라이언트가 제어 가능 (위조 가능)
- `http.user_agent`, `http.referer`
- `http.host` (리버스 프록시 앞단에서 검증 필요)
- `X-Forwarded-For`, `X-Real-IP` 같은 커스텀 헤더
- 바디, 쿠키 값
- **이 필드로 인증·인가 결정을 내리면 안 된다**

### 🟢 Cloudflare가 판정 (신뢰 가능)
- `ip.src` (TCP 레벨 소스 IP)
- `ip.src.country`, `ip.src.asnum`
- `cf.client.bot`, `cf.bot_management.*`
- `cf.waf.score.*`
- `cf.threat_score`

### 💡 실무 메모
X-Forwarded-For를 신뢰하는 백엔드가 있다면 Cloudflare에서 `ip.src` 값으로 **재작성**해 넘겨주는 설정이 필요하다. 그렇지 않으면 공격자가 헤더에 내부 IP를 박아 접근 제어를 우회할 수 있다.

---

## 4. 인코딩 — 같은 페이로드, 다른 모습

WAF 우회의 기본은 인코딩이다. 한 페이로드가 얼마나 다양하게 보일 수 있는지:

원본: `<script>alert(1)</script>`

| 인코딩 | 결과 |
|---|---|
| URL encode | `%3Cscript%3Ealert(1)%3C%2Fscript%3E` |
| Double URL | `%253Cscript%253E...` |
| HTML entity | `&lt;script&gt;alert(1)&lt;/script&gt;` |
| HTML numeric | `&#60;script&#62;...` |
| Unicode escape | `\u003cscript\u003e...` |
| Base64 (데이터 URL) | `data:text/html;base64,PHNjcmlwdD4uLi4=` |
| Mixed case | `<ScRiPt>alert(1)</sCrIpT>` |

### Cloudflare 변환 함수
> 출처: [Cloudflare Rules language functions](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/)

공식 지원 함수:

| 함수 | 용도 |
|---|---|
| `lower(string)` | 소문자 변환 |
| `upper(string)` | 대문자 변환 |
| `url_decode(string)` | URL 디코딩 (퍼센트 인코딩) |
| `len(string)` | 길이 |
| `regex_replace(source, pattern, replacement)` | 정규식 치환 |

> `html_decode()` 는 Cloudflare Rules language 공식 함수 목록에 없다. HTML 엔티티 디코딩은 정규식으로 따로 다뤄야 한다.

예시:
```
(lower(url_decode(http.request.uri.query)) contains "<script")
```

`url_decode`는 단일 패스다. **double encoding**을 잡으려면 중첩해야 한다: `url_decode(url_decode(...))`.

---

## 5. Content-Type과 파싱 엔진의 함정

같은 바이트도 Content-Type에 따라 서버 파싱 경로가 달라진다.

```http
Content-Type: application/json
Body: {"a":"1"}

Content-Type: application/xml
Body: <?xml version="1.0"?><a>1</a>

Content-Type: multipart/form-data; boundary=xxx
Body: (boundary로 분리된 필드)
```

### 우회 기법
- Content-Type을 `text/plain`으로 보내 JSON 파서 우회 후, 백엔드가 관대하게 JSON으로 재해석
- Content-Type 헤더 중복 으로 WAF와 백엔드가 서로 다른 값을 선택
- 비표준 charset으로 인코딩 혼동

### Cloudflare 대응
- `http.request.body.mime` 는 Cloudflare가 **실제 파싱한** MIME 타입이라 요청 헤더 값과 다를 수 있음
- 허용 Content-Type 화이트리스트 룰을 권장:
  ```
  (http.request.uri.path matches "^/api/" and
   not any(http.request.headers["content-type"][*] in {"application/json" "application/x-www-form-urlencoded"}))
  ```
  > 위 예시는 문법 개념 설명용이다. 실제 배포 전에는 Cloudflare Rule Expression Tester에서 검증해야 한다.

---

## 6. 실제 로그 한 줄 읽기

Cloudflare Logpush HTTP requests 데이터셋 예시 (축약):

> 출처: [Cloudflare Logpush HTTP requests fields](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/)

```json
{
  "ClientIP": "203.0.113.45",
  "ClientRequestMethod": "POST",
  "ClientRequestHost": "api.example.com",
  "ClientRequestPath": "/api/users/me",
  "ClientRequestURI": "/api/users/me?debug=1' OR '1'='1",
  "ClientRequestUserAgent": "sqlmap/1.7",
  "ClientCountry": "ru",
  "EdgeResponseStatus": 200,
  "SecurityAction": "allow",
  "BotScore": 3,
  "JA3Hash": "e7d705a3286e19ea42f587b344ee6865",
  "WAFAttackScore": 4,
  "WAFSQLiAttackScore": 2
}
```

> 참고: 과거 로그 필드 `WAFAction` 은 `SecurityAction` 으로 변경되었다. 필드 이름이 헷갈리면 공식 필드 레퍼런스를 확인하자.

### 이 요청에서 읽히는 것
1. `sqlmap/1.7` — 자동화 스캐너 UA
2. `' OR '1'='1` — 고전 SQLi
3. BotScore 3 — 봇 가능성 매우 높음
4. WAFSQLiAttackScore 2 — SQLi 공격 점수 매우 낮음(= 악성 가능성 매우 높음)

### 이 한 줄로 설계할 수 있는 룰 (스케치)

```
(http.user_agent contains "sqlmap") or
(cf.bot_management.score < 30 and http.request.uri contains "'") or
(cf.waf.score.sqli < 20)
```

> 이후 챕터에서 공격 클래스별로 더 정교한 룰을 만든다. 위 표현식은 개념 예시이며, 배포 전 Rule Expression Tester와 Log-only 모드로 검증해야 한다.

---

## 7. 체크포인트

<details>
<summary>Q1. X-Forwarded-For 값을 서버에서 `ip.src` 대신 사용하면 왜 위험한가?</summary>

XFF는 클라이언트가 자유롭게 설정 가능한 헤더다. 공격자가 `X-Forwarded-For: 10.0.0.1` 을 넣으면 내부망 IP로 위장해 IP 기반 허용 정책을 우회할 수 있다. Cloudflare에서는 `ip.src`(실제 TCP 소스)를 써야 한다.
</details>

<details>
<summary>Q2. `http.request.uri.query contains "<script>"` 만으로 XSS를 잡을 수 없는 이유는?</summary>

1. URL 인코딩 시 `%3Cscript%3E`로 바뀌어 리터럴 매칭 실패
2. 대소문자 변형 `<Script>`에 걸리지 않음
3. HTML entity `&lt;script&gt;` 나 이벤트 핸들러 기반 XSS(`<img onerror=...>`)를 커버하지 못함

→ `lower(url_decode(...))` 정규화 + 정규식 기반 매칭이 필요
</details>

<details>
<summary>Q3. `cf.waf.score.sqli` 값이 5일 때 어떤 판단을 내려야 하나?</summary>

점수는 낮을수록 위험. 5는 매우 강한 SQLi 의심 신호. 해당 경로·국가·봇 점수와 결합해 Block 또는 Managed Challenge로 대응. 단독으로 Block 걸면 오탐 가능성이 있으니 Log → Challenge → Block 단계로 올린다.
</details>

---

## 더 읽을거리

- [Cloudflare Rules language fields reference](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/)
- [Cloudflare Rules language functions](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/)
- [Cloudflare WAF attack score](https://developers.cloudflare.com/waf/about/waf-attack-score/)
- [Cloudflare Logpush HTTP requests fields](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/)
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

**다음 챕터**: `02_owasp_top10.md` — OWASP Top 10과 WAF 커버리지 매트릭스
