# Security Technology Research Institute — Learning Materials

웹 공격·WAF 운영·보안 탐지에 관한 개인 학습 자료 모음. Cloudflare WAF 운영 관점에서 정리한다.

## 목차

### 웹 공격 기초 시리즈
- [01. HTTP 요청 해부 — WAF가 보는 시점](docs/web-attack/01_http_request_anatomy.md)
- [02. OWASP Top 10 × WAF 커버리지 매트릭스](docs/web-attack/02_owasp_top10.md)
- [03. WAF 기초 — 동작 원리와 룰 설계](docs/web-attack/03_waf_basics.md)

이후 챕터는 순차적으로 추가 예정.

## 작성 원칙

1. **사실 기반** — 제품명·필드명·스펙·CVE 번호는 공식 문서에서 확인한 내용만 사용한다
2. **실무 지향** — 개념만 나열하지 않고, 실제 룰 표현식·로그 예시·체크리스트를 붙인다
3. **참조는 실제 링크만** — 깨지거나 존재하지 않는 링크는 싣지 않는다
4. **한국어** — 용어는 한국어 우선, 공식 명칭은 원어 병기

## 대상 독자

- WAF·SIEM을 운영하는 보안 담당자
- 웹 공격 탐지·대응 로직을 직접 설계해야 하는 엔지니어
- OWASP Top 10 수준의 이해를 넘어 룰 한 줄을 직접 작성하고 싶은 사람

## 사용법

각 문서는 단독으로 읽을 수 있도록 작성되어 있다. 순서대로 읽으면 HTTP 요청 구조 → 공격 분류 → WAF 룰 설계 흐름을 따라갈 수 있다.

## 라이선스

[MIT](LICENSE)
