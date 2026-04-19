# Security Technology Research Institute — Learning Materials

웹 공격·WAF 운영·AI 보안·보안 탐지에 관한 개인 학습 자료 모음. 실무 운영 관점에서 정리한다.

## 목차

### 웹 공격 기초 시리즈
- [01. HTTP 요청 해부 — WAF가 보는 시점](docs/web-attack/01_http_request_anatomy.md)
- [02. OWASP Top 10:2025 × WAF 커버리지 매트릭스](docs/web-attack/02_owasp_top10.md)
- [03. WAF 기초 — 동작 원리와 룰 설계](docs/web-attack/03_waf_basics.md)
- [04. SQL Injection — 패턴, 우회, WAF 대응](docs/web-attack/04_sql_injection.md)
- [05. Cross-Site Scripting (XSS) — 컨텍스트·우회·CSP 조합](docs/web-attack/05_xss.md)
- [06. Command Injection & SSRF — RCE와 내부 접근의 최단 경로](docs/web-attack/06_command_injection_ssrf.md)
- [07. Path Traversal & File Inclusion — 경로 정규화 우회](docs/web-attack/07_path_traversal_lfi.md)
- [이후 작업 로드맵](docs/web-attack/ROADMAP.md)

### AI 보안 시리즈
- [00. AI 보안 담당자를 위한 LLM 기본기 — 용어·모델·API·실습](docs/ai-security/00_llm_fundamentals_for_security.md)
- [01. 공격 AI 지형도 — Claude Mythos 이후](docs/ai-security/01_offensive_ai_landscape.md)
- [02. AI 기반 공격 유형 정리 — 실제 사고 중심 분류](docs/ai-security/02_ai_attack_taxonomy.md)
- [03. 프런티어 모델 시대의 방어 전략 — 속도 전쟁을 가정한 설계](docs/ai-security/03_mythos_ready_defense.md)
- [04. OWASP LLM Top 10:2025 방어 레시피 — 항목별 구현 가이드](docs/ai-security/04_llm_top10_defense_recipes.md)
- [05. 에이전트 보안 실전 플레이북 — MCP·툴 호출·샌드박스](docs/ai-security/05_agent_security_playbook.md)
- [06. Claude Code CLI 보안 — 설정·훅·권한·MCP·실습](docs/ai-security/06_claude_code_cli_security.md)
- [07. 실전 종합 랩 — Claude Code 보안 모니터링 구축](docs/ai-security/07_integrated_labs.md)
- [08. 한국 금융권 AI 보안 실무 가이드 (2026-04 기준)](docs/ai-security/08_ai_governance_framework.md)

이후 챕터는 순차적으로 추가 예정.

## 대상 독자

- WAF·SIEM을 운영하는 보안 담당자
- 웹 공격 탐지·대응 로직을 직접 설계해야 하는 엔지니어
- AI/LLM 서비스 도입 시 보안 통제를 설계해야 하는 엔지니어
- OWASP Top 10 / LLM Top 10 수준의 이해를 넘어 실전 룰·정책을 직접 작성하고 싶은 사람

## 사용법

각 문서는 단독으로 읽을 수 있도록 작성되어 있다. 웹 공격 시리즈는 HTTP 요청 구조 → 공격 분류 → WAF 룰 설계 순으로, AI 보안 시리즈는 LLM 기본기 → 공격 지형도 → 공격 유형 → 방어 전략 → 항목별 레시피 → 에이전트 실전 → CLI 보안 → 종합 랩 → 금융권 실무 가이드 순으로 읽으면 흐름을 따라갈 수 있다.

## 라이선스

[MIT](LICENSE)
