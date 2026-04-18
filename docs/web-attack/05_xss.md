# 05. Cross-Site Scripting (XSS) — 컨텍스트·우회·WAF와 CSP 조합

> OWASP Top 10:2025 기준 **A05 Injection**에 속한다.

## 학습 목표
- XSS 3가지 유형(Reflected / Stored / DOM)의 차이와 대응 지점을 구분한다
- **렌더링 컨텍스트**에 따라 페이로드 모양이 달라지는 이유를 설명할 수 있다
- Cloudflare `cf.waf.score.xss`, 커스텀 룰, CSP(Content Security Policy)의 역할을 분리해서 설계한다

---

## 1. XSS란

애플리케이션이 사용자 입력을 **HTML/JS 컨텍스트에 안전하게 이스케이프하지 않고** 렌더링할 때, 공격자가 삽입한 스크립트가 피해자 브라우저에서 실행된다.

### 영향
- 세션 쿠키 탈취 (`document.cookie`)
- 키로깅·클릭 하이재킹
- 피해자 권한으로 임의 요청 (CSRF 대체)
- 피싱 UI 오버레이

### 근본 원인
- **컨텍스트별 출력 이스케이프 누락** (HTML body vs 속성 vs JS 문자열 vs URL)
- `innerHTML`, `document.write`, `eval`, `dangerouslySetInnerHTML` 등 sink 함수 남용
- 서버는 이스케이프했지만 **클라이언트가 다시 innerHTML에 박는** 경우

---

## 2. XSS 유형

### 2.1 Reflected XSS
공격 페이로드가 요청 파라미터로 들어가서 **즉시 응답에 반사**된다.
```
https://example.com/search?q=<script>alert(1)</script>
```
피해자가 링크를 클릭하는 순간 발동. 주로 피싱으로 배포.

### 2.2 Stored XSS
페이로드가 **서버에 저장**되어 이후 모든 열람자에게 실행된다. (댓글, 게시글, 프로필, 관리자 패널 로그 등)

영향 범위가 가장 크다. 특히 **관리자 화면에 저장된 XSS**는 권한 상승의 지름길.

### 2.3 DOM-based XSS
서버를 거치지 않고 **클라이언트 JS가 URL 파라미터·해시를 읽어 DOM에 박아 넣는** 경우.
```js
document.getElementById('out').innerHTML = location.hash.slice(1)
```
→ `#<img src=x onerror=alert(1)>` 로 실행.

서버 응답에는 페이로드가 없기 때문에 **WAF가 탐지하지 못한다**. 앱 레이어 대응 필수.

---

## 3. 렌더링 컨텍스트가 페이로드를 결정한다

같은 입력도 어디에 들어가느냐에 따라 **필요한 이스케이프가 다르다**. 이걸 모르면 잘못된 방어를 한다.

### 3.1 HTML body 컨텍스트
```html
<div>USER_INPUT</div>
```
페이로드: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`

### 3.2 HTML 속성 컨텍스트
```html
<input value="USER_INPUT">
```
페이로드: `" onmouseover="alert(1)` (따옴표 탈출)
따옴표 없는 속성: `<img src=USER_INPUT>` → `x onerror=alert(1)`

### 3.3 JavaScript 문자열 컨텍스트
```html
<script>var x = "USER_INPUT";</script>
```
페이로드: `";alert(1);//` (문자열 종료 + 삽입)

### 3.4 URL 컨텍스트
```html
<a href="USER_INPUT">
```
페이로드: `javascript:alert(1)`

### 3.5 JSON/JS 데이터 컨텍스트
```html
<script>var data = USER_INPUT;</script>
```
JSON.parse 없이 바로 JS로 읽힘 → 임의 JS 삽입 가능.

**요점**: 방어는 **출력 컨텍스트별 이스케이프**. WAF는 이 레이어를 보조만 한다.

---

## 4. 자주 보이는 페이로드

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<a href="javascript:alert(1)">x</a>
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<math><brute href=javascript:alert(1)>
"><script>alert(1)</script>
'-alert(1)-'
```

### 공통 요소
- 태그: `<script>`, `<img>`, `<svg>`, `<iframe>`, `<body>`, `<input>`, `<details>`
- 이벤트 핸들러: `onerror`, `onload`, `onfocus`, `onmouseover`, `ontoggle`, `onanimationstart`
- 프로토콜: `javascript:`, `data:text/html,...`
- 문자열 탈출: `"`, `'`, `>`, `<`, `` ` ``

---

## 5. WAF 우회 기법

### 5.1 인코딩
```
%3Cscript%3Ealert(1)%3C%2Fscript%3E   -- URL
%253Cscript%253E...                   -- 이중 URL
&lt;script&gt;alert(1)&lt;/script&gt; -- HTML entity
&#60;script&#62;...                   -- HTML numeric
&#x3C;script&#x3E;...                 -- HTML hex
\u003cscript\u003e...                 -- Unicode escape (JS 컨텍스트)
```

### 5.2 케이스·공백 변형
```html
<ScRiPt>alert(1)</sCrIpT>
<script >alert(1)</script>
<script/>alert(1)</script>
<script\tsrc=...>
```

### 5.3 태그 없는 XSS (속성 기반)
```html
onerror=alert(1) src=x
" autofocus onfocus=alert(1) "
```
`<script>` 키워드만 찾는 룰은 뚫린다.

### 5.4 이벤트 핸들러의 다양성
고전 `onerror`/`onload` 외에도 HTML5에서 **100개 이상의 이벤트 핸들러**가 있다. 개별 키워드 나열은 끝이 없다. → 구조적 매칭(`on\w+\s*=`)이 낫다.

### 5.5 JavaScript URL 우회
```
javascript:alert(1)
java\tscript:alert(1)
JaVaScRiPt:alert(1)
javascript&#58;alert(1)
```

### 5.6 주석·백틱·템플릿 리터럴
```html
<script>/*x*/alert/*x*/(1)</script>
<script>alert`1`</script>
<script>eval(atob('YWxlcnQoMSk='))</script>   -- base64
```

---

## 6. Cloudflare 기본 제공 방어

### 6.1 Managed Ruleset
광범위한 XSS 시그니처 포함. `<script>`, `onerror=`, `javascript:` 등 전형 패턴을 잡는다.

### 6.2 WAF Attack Score
`cf.waf.score.xss`는 **1~99 범위**(낮을수록 공격 의심). SQLi와 마찬가지로 경로·봇점수와 결합해 판정.

> 공식 문서: https://developers.cloudflare.com/waf/about/waf-attack-score/

### 6.3 한계
- DOM XSS는 서버 요청에 페이로드가 안 실리므로 **WAF로 탐지 불가**
- 고도화된 인코딩·제로데이 페이로드는 시그니처에 없을 수 있음

---

## 7. 커스텀 룰 설계 예시

### 7.1 Attack Score 기반
```
(http.request.uri.path matches "^/(search|comment|review)") and
(cf.waf.score.xss lt 20)
→ Managed Challenge
```

### 7.2 이벤트 핸들러 구조 매칭
```
(lower(url_decode(http.request.uri.query)) matches
  "on[a-z]+\s*=\s*[\"']?[^\"'>]*\(")
→ Block
```
`on<event>=` 형태 + 함수 호출 괄호 근접 매칭. 개별 이벤트명 나열보다 견고.

### 7.3 `javascript:` 프로토콜 탐지
```
(lower(url_decode(http.request.uri.query)) contains "javascript:") or
(lower(url_decode(http.request.uri.query)) contains "vbscript:") or
(lower(url_decode(http.request.uri.query)) contains "data:text/html")
→ Managed Challenge
```

### 7.4 `<script>` 변형 대응
```
(lower(url_decode(http.request.uri.query)) matches
  "<\s*script[\s/>]")
→ Managed Challenge
```
`<script>`, `< script>`, `<script/>` 등을 한 번에.

### 7.5 조합 판정
```
(cf.waf.score.xss lt 30) and
(http.request.method in {"GET" "POST"}) and
(http.request.uri.path matches "^/api/") and
(cf.bot_management.score lt 40)
→ Block
```

---

## 8. CSP — WAF 너머의 브라우저 방어

WAF가 막지 못하는 DOM XSS·우회 페이로드에 대한 최후 방어선이 **Content Security Policy**다. 브라우저가 실행 시점에 스크립트 출처를 강제한다.

### 8.1 기본 예시
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'; object-src 'none'; base-uri 'none';
```

### 8.2 핵심 디렉티브
| 디렉티브 | 의미 |
|---|---|
| `default-src` | 모든 리소스 기본 출처 |
| `script-src` | JS 실행 허용 출처 |
| `style-src` | CSS 출처 |
| `img-src` | 이미지 출처 |
| `object-src 'none'` | Flash/plugin 차단 (거의 필수) |
| `base-uri 'none'` | `<base>` 태그 조작 방지 |
| `frame-ancestors` | 클릭재킹 방지 (X-Frame-Options 대체) |
| `report-uri` / `report-to` | 위반 리포트 수집 |

### 8.3 Nonce vs Hash
- **Nonce**: 서버가 매 응답마다 랜덤 값을 헤더+스크립트 태그에 박음. `<script nonce="abc">...`
- **Hash**: 인라인 스크립트 해시를 CSP에 나열

`unsafe-inline`은 피할 것. CSP의 의미가 사라진다.

### 8.4 CSP도 완벽은 아니다
- JSONP 엔드포인트가 허용 출처에 있으면 우회 가능
- `'self'` + 사용자 업로드 가능 도메인이면 끝
- **Trusted Types**(최신 브라우저) 도입으로 DOM sink 자체를 방어

---

## 9. 실제 로그 예시

```json
{
  "ClientIP": "198.51.100.200",
  "ClientRequestMethod": "GET",
  "ClientRequestHost": "app.example.com",
  "ClientRequestURI": "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
  "ClientRequestUserAgent": "Mozilla/5.0 ...",
  "EdgeResponseStatus": 403,
  "SecurityAction": "block",
  "WAFAttackScore": 8,
  "WAFXSSAttackScore": 5,
  "BotScore": 12
}
```

### 해석
- URL 디코드: `q=<img src=x onerror=alert(1)>` — 전형적 속성 기반 XSS
- `WAFXSSAttackScore=5` — 매우 강한 XSS 의심
- `BotScore=12` — 봇 가능성 높음
- `SecurityAction=block` — 이미 차단

---

## 10. 운영 체크리스트

### 10.1 탐지
- [ ] Managed Ruleset XSS 룰 활성화
- [ ] `cf.waf.score.xss` 기반 경로별 룰 (Log → Challenge → Block)
- [ ] 이벤트 핸들러 구조 매칭 룰
- [ ] `javascript:` / `data:text/html` 프로토콜 탐지

### 10.2 애플리케이션
- [ ] 출력 컨텍스트별 이스케이프 (HTML body / 속성 / JS / URL)
- [ ] `innerHTML`, `eval`, `document.write` 전면 금지
- [ ] React `dangerouslySetInnerHTML` 코드 리뷰
- [ ] CSP with nonce (unsafe-inline 제거)
- [ ] 쿠키 `HttpOnly`, `Secure`, `SameSite=Lax/Strict`

### 10.3 관측
- [ ] CSP `report-to` 엔드포인트 운영
- [ ] Logpush → SIEM에 XSS 점수·URI 저장
- [ ] 위반 리포트 급증 시 알림

---

## 11. 체크포인트

<details>
<summary>Q1. DOM-based XSS를 WAF로 막을 수 없는 이유는?</summary>

DOM XSS는 **클라이언트 JS가 `location.hash`·`location.search`·`document.referrer` 등을 읽어 직접 DOM에 박는다**. `#` 뒤의 해시는 HTTP 요청에 포함되지 않아 **서버·WAF 모두 볼 수 없다**. 방어는 앱 레이어(안전한 sink, Trusted Types, DOMPurify)와 CSP 조합.
</details>

<details>
<summary>Q2. `<script>` 키워드만 차단하면 왜 부족한가?</summary>

- HTML5에는 이벤트 핸들러 기반 XSS가 무수히 많음(`<img onerror=...>`, `<svg onload=...>`)
- 케이스 변형·인코딩·공백 삽입으로 우회 가능
- 속성 컨텍스트에서는 태그 없이 `" onmouseover=alert(1) "` 만으로 발동
- → `on\w+\s*=` 구조 매칭, 정규화 후 검사, 점수 기반 탐지를 함께 써야 한다
</details>

<details>
<summary>Q3. CSP에 `'unsafe-inline'`을 넣으면 어떻게 되는가?</summary>

인라인 `<script>...</script>`와 인라인 이벤트 핸들러 실행이 허용돼 **CSP의 XSS 방어 효과가 사실상 사라진다**. Nonce 또는 Hash 기반으로 인라인을 제한하거나, 아예 외부 JS 파일로만 로드하도록 리팩터링해야 한다.
</details>

---

## 12. 더 읽을거리

- OWASP — Cross Site Scripting (XSS): https://owasp.org/www-community/attacks/xss/
- OWASP Cheat Sheet — XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet — DOM based XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — XSS: https://portswigger.net/web-security/cross-site-scripting
- MDN — Content Security Policy (CSP): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- MDN — Trusted Types: https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API
- Cloudflare — WAF attack score: https://developers.cloudflare.com/waf/about/waf-attack-score/

---

**다음 챕터**: `06_command_injection_ssrf.md` — OS Command Injection과 SSRF 페이로드, IMDS 타겟팅, 인바운드 탐지
