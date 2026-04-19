# 02. AI 기반 공격 유형 정리 — 실제 사고 중심 분류

## 학습 목표
- 2025~2026년 실제 발생한 AI 관련 침해·취약점을 **공격 유형별로 분류**해 이해한다
- OWASP LLM Top 10:2025와 OWASP Agentic Apps Top 10:2026의 **차이**와 **매핑**을 파악한다
- 방어 룰 설계·MCP 통합 검토·사내 LLM 도입 시 **어떤 공격면이 실재하는지** 실무 관점에서 정리한다

> 이 문서는 01 챕터의 "공격 AI 지형도"를 이어받아 **공격 유형 카탈로그**로 들어간다. 각 유형은 실제 CVE 또는 공개 사고 사례를 근거로 한다.

---

## 1. 공격 유형 5대 분류

AI 관련 공격은 방어 관점에서 다섯 갈래로 나눠보면 룰·통제 설계가 쉽다.

| 분류 | 핵심 벡터 | 대표 사례 | OWASP 매핑 |
|---|---|---|---|
| **A. 모델 입력 공격** | 프롬프트 인젝션(직접·간접) | GitHub MCP 유출 | LLM01 / ASI01 |
| **B. 에이전트 도구 악용** | 정당 권한으로 위험 도구 연쇄 호출 | Supabase Cursor 토큰 유출 | LLM06 / ASI02, ASI03 |
| **C. 공급망·생태계 오염** | 악성 패키지, slopsquatting, 모델·플러그인 오염 | `react-codeshift` slopsquat | LLM03 / ASI04 |
| **D. AI 보조 공격 자동화** | LLM이 정찰·피싱·익스플로잇 체인 생성 | 딥페이크 Zoom CFO 사기 | (OWASP 외, 공격자 측 도구) |
| **E. MCP·에이전트 런타임 취약점** | MCP 서버·클라이언트 자체의 RCE·인젝션 | CVE-2025-6514 `mcp-remote` | ASI05, ASI07 |

아래에서 각 분류를 공식 사례·OWASP 정의·방어 관점으로 다룬다.

---

## 2. A. 모델 입력 공격 — 프롬프트 인젝션

### 2.1 OWASP 정의
**LLM01 Prompt Injection** (OWASP Top 10 for LLM Apps 2025): 사용자 입력이 모델 동작을 변조해 의도치 않은 행위를 유발. 2025판에서 직접/간접 인젝션을 명시적으로 구분했다.

**ASI01 Agent Goal Hijack** (OWASP Agentic 2026): 에이전트의 **목표·계획·의사결정 경로** 자체를 탈취. 단순 출력 조작에서 한 단계 더 나아간 것.

### 2.2 직접 vs 간접
- **직접 인젝션**: 사용자가 직접 프롬프트에 악의 지시를 넣는 것. ChatGPT 탈옥 시도가 대표적. 위협은 **이 사용자 자신**으로 한정되는 경우가 많다.
- **간접 인젝션**: 모델이 읽어오는 **외부 콘텐츠**(이슈, PR 설명, 웹페이지, 이메일, 파일)에 공격자가 미리 심어둔 지시가 포함되는 것. **제3자 공격**의 주요 벡터.

### 2.3 실제 사고 — GitHub MCP 프롬프트 인젝션 (2025-05)
- **발견**: Invariant Labs (simonwillison.net 정리)
- **경로**: 공격자가 공개 레포 이슈에 악성 프롬프트 작성 → 피해자가 자기 AI 코딩 어시스턴트(Cursor/Claude Code 등)에게 "내 열린 이슈 처리해줘"라고 지시 → 어시스턴트가 공식 **GitHub MCP 서버**를 통해 해당 이슈 읽음 → 숨겨진 지시대로 **프라이빗 레포 내용·급여 정보를 공개 PR로 커밋**
- **본질**: MCP 서버 자체는 안전했다. 인증·권한도 정상이었다. **에이전트가 "신뢰 범위"를 혼동**한 것
- **참조**:
  - https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/
  - https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/

### 2.4 방어 관점에서 봐야 할 포인트
- **입력 출처별 신뢰 등급**을 모델에게 명시적으로 주입 ("다음 콘텐츠는 UNTRUSTED 외부 이슈입니다")
- **쓰기·파괴 도구는 인간 승인 루프** 강제 (git push, 이메일 전송, DB 삭제 등)
- **샌드박스 내 도구 호출** 로그 전량 수집
- **페르소나 기반 시스템 프롬프트 방어는 우회 가능** — 방어 주 수단으로 쓰지 말 것

---

## 3. B. 에이전트 도구 악용 — Excessive Agency의 실사례

### 3.1 OWASP 정의
- **LLM06 Excessive Agency**: 에이전트에게 필요 이상의 도구·권한·자율성을 부여해 남용을 초래
- **ASI02 Tool Misuse & Exploitation**: 에이전트가 **정당 권한 내에서** 도구를 위험하게 조합·재귀 호출
- **ASI03 Agent Identity & Privilege Abuse**: 위임 권한의 모호함 또는 혼동을 이용한 Confused Deputy 패턴

### 3.2 실제 사고 — Supabase Cursor 에이전트 토큰 유출 (2025 중반)
- **구성**: 고객 지원 티켓을 자동 처리하는 Cursor 에이전트, Supabase에 **service-role** 권한으로 연결
- **공격**: 공격자가 지원 티켓 본문에 SQL 인젝션형 프롬프트 작성 → 에이전트가 충실히 실행 → 내부 **통합 토큰을 공개 지원 스레드에 그대로 출력**
- **본질**: 권한 경계 실패. 에이전트가 **고객(저신뢰 입력)**과 **내부 DB(고신뢰 도구)** 사이에서 **신뢰 경계를 번역**해야 했는데 그대로 통과시킴
- **참조**: https://authzed.com/blog/timeline-mcp-breaches

### 3.3 방어 설계 체크리스트
- **최소 권한**: 에이전트가 쓰는 DB 계정은 RO 우선, RW는 특정 테이블·특정 컬럼으로 제한
- **출력 필터링**: 응답에서 토큰·시크릿 패턴(`ghp_*`, `sk-*`, `xox[bp]-*`) 마스킹
- **도구 화이트리스트 + 레이트 리밋**: 한 세션에서 호출 가능한 도구와 빈도를 제한
- **휴먼 인 더 루프**: 삭제·외부 전송·권한 변경은 반드시 인간 승인

---

## 4. C. 공급망·생태계 오염

### 4.1 OWASP 정의
- **LLM03 Supply Chain** (2025 기준 상승): 모델·데이터셋·플러그인 공급망 취약점
- **ASI04 Agentic Supply Chain Compromise**: **동적으로 신뢰하는** 외부 에이전트·툴·스키마·프롬프트 오염

### 4.2 Slopsquatting — LLM 환각을 노린 새 유형
**정의**: LLM이 코드 생성 시 **존재하지 않는 패키지명**을 추천하는 경향을 악용. 공격자가 그 "환각 이름"을 미리 npm/PyPI에 **선점**해두면 사용자가 그대로 설치.

- **연구 결과** (USENIX Security 2025, 16개 모델·57.6만 샘플)
  - 오픈소스 모델 환각률 **21.7%**
  - 상용 모델 환각률 **5.2%**
- **실제 사례**
  - **`react-codeshift`** (2026-01, npm): LLM이 존재하지 않는 이 이름을 실제로 추천하자 공격자가 선점 등록 → 악성 postinstall 스크립트 포함
  - **`huggingface-cli`** 빈 PoC 패키지: 3개월간 3만+ 다운로드 기록, 안전성 연구용이었지만 공격 가능성 실증
- **참조**:
  - https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks
  - https://www.helpnetsecurity.com/2025/04/14/package-hallucination-slopsquatting-malicious-code/

### 4.3 기존 typosquatting과의 차이
| 구분 | Typosquatting | Slopsquatting |
|---|---|---|
| 타겟 | 사람의 오타 | LLM의 환각 |
| 이름 예시 | `reqeusts` (requests 오타) | `react-codeshift` (실재 X, LLM이 자주 추천) |
| 탐지 | 정식 패키지명과의 편집거리 | LLM 응답 로그 + 패키지 등록 이름 교차 |
| 규모 | 개별 오타 타겟팅 | **LLM 응답 한 번에 수천 명**이 같은 가짜 이름 설치 시도 |

### 4.4 방어 체크리스트
- CI에서 **설치 전 패키지명 화이트리스트** 검증
- 내부 사설 레지스트리(Nexus/Artifactory)로 **알려진 패키지만** 프록시
- LLM이 생성한 `requirements.txt`·`package.json`은 **사람 리뷰 필수**
- Socket·Snyk·Semgrep Supply Chain 같은 도구로 신규 패키지 의심도 스캔
- LLM이 추천한 패키지가 **최근 7일 내 신규 등록**이면 경고

---

## 5. D. AI 보조 공격 자동화

### 5.1 딥페이크 금융 사기
- **2024 홍콩**: Arup 엔지니어링, Zoom 회의에서 CFO·동료를 전원 딥페이크로 재현, **US$25M 송금**. AI 보안 서사의 전환점
- **2025-03 싱가포르**: 다국적 기업, Zoom 딥페이크 CFO에 의한 **US$499K 피해**
- **2025 Q1 북미**: 딥페이크 사기 총손실 **US$200M 이상**, 딥페이크 비싱 **1,600% 증가**
- **참조**:
  - https://www.tookitaki.com/blog/deepfake-ceo-scam-singapore-2025
  - https://www.dandodiary.com/2025/08/articles/cyber-liability/

### 5.2 방어 절차
- **결제·권한 변경은 다중 채널 확인 강제**: 영상 회의 지시 + 반드시 콜백 또는 사내 메신저 이중 확인
- **임원 목소리·얼굴을 학습시킨 탐지기** 도입은 **오탐 많음** — 절차적 방어가 더 효과적
- 사내 **코드워드** 운영: 긴급 송금 지시에 오늘 날짜 기반 코드워드 요구
- 피싱 훈련 메일에 **AI 생성본 포함** — 기존 단순 피싱 훈련과 구분되는 난이도

### 5.3 자동화된 정찰·익스플로잇
01 챕터의 Cybench·엔터프라이즈 32-step 지표와 연결. 공격 측이 에이전트 루프로 정찰·시나리오 생성·페이로드 시도를 자동화. 방어 측 대응은 **탐지·격리의 자동화**로만 속도 대응 가능 — 개별 CVE 대응보다 **플레이북 자동 실행**에 투자.

---

## 6. E. MCP·에이전트 런타임 취약점

**가장 최근 터진 영역**. AI 공격이 아니라 **AI를 쓰기 위한 인프라 자체의 클래식 취약점**이다.

### 6.1 주요 CVE (2025)

| CVE | 대상 | 유형 | CVSS | 설명 |
|---|---|---|---|---|
| **CVE-2025-6514** | `mcp-remote` (437K+ DL) | OS Command Injection | **9.6** | Claude Desktop 등에서 널리 쓰이는 원격 MCP 프록시에서 RCE |
| **CVE-2025-68143** | Anthropic `mcp-server-git` | Path bypass | 체인 | 경로 검증 우회 |
| **CVE-2025-68144** | 동일 | `git_init` 악용 | 체인 | 악성 저장소 초기화 |
| **CVE-2025-68145** | 동일 | `git_diff` arg injection | 체인 | 인자 주입 → RCE |
| **CVE-2025-53967** | Framelink Figma MCP | Command Injection | 7.5 | 디자인 도구 MCP의 커맨드 주입 |
| **CVE-2025-64106** | Cursor MCP 설치 플로우 | 임의 명령 실행 | 8.8 | MCP 도구 설치 과정에서 RCE |

**통합 DB**: https://vulnerablemcp.info/

### 6.2 MCP 스펙 Security Best Practices (2025-06-18)
공식 스펙이 보안 요구사항을 명시했다:
- **Token Passthrough 금지**: 에이전트가 받은 토큰을 다른 서비스에 그대로 넘기지 말 것
- **Confused Deputy 방어**: 에이전트 ID와 사용자 ID를 분리 유지
- **Session Hijacking 방어**: 세션 토큰 재사용·유출 경로 차단
- **OAuth PKCE 필수**: OAuth 흐름에서 PKCE 강제

참조:
- https://modelcontextprotocol.io/specification/2025-11-25
- https://www.anthropic.com/engineering/code-execution-with-mcp
- https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp

### 6.3 사내 MCP 도입 전 체크
- [ ] 사용 예정 MCP 서버의 **최신 CVE 목록** 확인 (`vulnerablemcp.info`)
- [ ] 외부 MCP 서버를 **직접 호출하지 말고 사내 프록시**로 경유
- [ ] 에이전트가 쓸 수 있는 MCP 도구 목록을 **명시적 allowlist**로 관리
- [ ] MCP 도구 호출 전량을 **감사 로그**로 수집
- [ ] OAuth 흐름은 **PKCE 강제**, 토큰은 단기 + 최소 스코프
- [ ] `mcp-remote` 등 프록시형 서버는 **고위험**으로 분류, 업데이트 주기 짧게

---

## 7. OWASP Top 10 교차 매핑

사내 AI 시스템 리뷰 체크리스트로 쓸 수 있도록 두 표준을 한 표로 정리.

### 7.1 OWASP LLM Top 10:2025

| ID | 이름 | 방어자 관점 핵심 |
|---|---|---|
| LLM01 | Prompt Injection | 입력 출처별 신뢰 등급 부여, 도구 호출 샌드박스 |
| LLM02 | Sensitive Information Disclosure | 출력 필터링, PII·시크릿 마스킹 (**6위 → 2위 상승**) |
| LLM03 | Supply Chain | 모델·플러그인·데이터셋 출처 검증 (**5위 → 3위 상승**) |
| LLM04 | Data and Model Poisoning | RAG·파인튜닝 데이터 오염 탐지 |
| LLM05 | Improper Output Handling | 응답 검증·sanitization (예: XSS로 재생성된 HTML) |
| LLM06 | Excessive Agency | **도구 권한 최소화, 인간 승인 루프** |
| LLM07 | **System Prompt Leakage** (신규) | 시스템 프롬프트를 보안 경계로 쓰지 말 것 |
| LLM08 | **Vector and Embedding Weaknesses** (신규) | RAG 저장소 권한 분리, 멀티테넌시 격리 |
| LLM09 | Misinformation (구 Overreliance) | 허위 정보 생성·전파 |
| LLM10 | **Unbounded Consumption** (확장) | 비용·토큰·쿼리 quota, 비정상 패턴 탐지 |

참조: https://genai.owasp.org/llm-top-10/

### 7.2 OWASP Agentic Apps Top 10:2026 (ASI01~ASI10)

| ID | 이름 | LLM Top 10 대비 신규 관점 |
|---|---|---|
| ASI01 | Agent Goal Hijack | **목표 자체의 탈취** |
| ASI02 | Tool Misuse & Exploitation | 정당 권한 내 위험 조합 |
| ASI03 | Agent Identity & Privilege Abuse | Confused Deputy |
| ASI04 | Agentic Supply Chain Compromise | **동적으로 신뢰하는** 외부 에이전트·스키마 오염 |
| ASI05 | Unexpected Code Execution | 에이전트 생성·트리거 코드 격리 |
| ASI06 | Memory & Context Poisoning | **장기 메모리 공격면** |
| ASI07 | Insecure Inter-Agent Communication | 플래너-실행자 메시지 변조 |
| ASI08 | Cascading Agent Failures | 에이전트 망 전체 전파 |
| ASI09 | Human-Agent Trust Exploitation | 인간의 과신 유도 |
| ASI10 | Rogue Agents | **창발 자율성**으로 통제 벗어남 |

참조: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

### 7.3 두 표준의 관계
- LLM Top 10은 **모델을 가진 앱**의 리스크
- Agentic Top 10은 **행위자(principal)로서의 에이전트** 리스크
- 두 개는 **상호 배타가 아닌 포함 관계**. 에이전트 앱은 두 리스트를 **모두** 체크해야 한다
- 이 문서의 5대 분류(A~E)는 두 표준을 **공격 벡터 중심**으로 재구성한 것

---

## 8. 사내 도입 전 결정 프레임워크

이 장에서 다룬 공격 유형을 기반으로 사내 AI 시스템을 검토할 때의 우선순위 질문들.

### 8.1 "어떤 에이전트를 허용할 것인가"
1. 이 에이전트가 **읽는 외부 콘텐츠**는 무엇인가? → 프롬프트 인젝션 벡터 (A)
2. **쓰기·파괴 도구**에 접근하는가? → Excessive Agency (B)
3. 의존하는 **MCP 서버·플러그인**은 최신 CVE가 없는가? → 런타임 취약점 (E)
4. **모델 공급자·가중치**의 출처는 믿을 만한가? → 공급망 (C)

### 8.2 "어떤 출력 경로를 허용할 것인가"
1. 에이전트 응답이 **사용자에게 직접** 렌더링되는가? → LLM05 improper output handling
2. **외부 시스템**(Slack, GitHub, DB)에 쓰기 가능한가? → 인간 승인 필요 여부
3. **다른 에이전트**에게 메시지를 보내는가? → ASI07 inter-agent communication

### 8.3 "어떤 로그를 남길 것인가"
- 모든 프롬프트 입력 (최소 해시 + 메타)
- 모든 도구 호출 (arg, 결과, 에러)
- 모든 외부 콘텐츠 읽기 (URL, 해시)
- 모든 MCP 세션 (토큰 식별자, 스코프, TTL)
- 에이전트 자기 결정 로그 (계획, 수정, 포기)

---

## 9. 체크포인트

<details>
<summary>Q1. 프롬프트 인젝션과 Jailbreak의 차이는?</summary>

- **Jailbreak**: **모델 자체의 안전장치**를 풀어 의도된 필터를 회피. "할머니 놀이" 같은 고전 기법. 주로 **직접 인젝션**.
- **Prompt Injection**: **애플리케이션 레이어의 신뢰 경계**를 공격. 모델이 외부 콘텐츠를 읽을 때 거기 섞인 지시를 따르게 만드는 것. **간접 인젝션**이 더 파괴적.
- 2023년에는 둘을 섞어 쓰는 경우가 많았지만 2025년 OWASP가 공식적으로 구분했다.
</details>

<details>
<summary>Q2. Slopsquatting은 기존 공급망 공격과 무엇이 다른가?</summary>

**규모와 재현성**이 다르다.
- Typosquatting은 **개인 오타**에 의존해 한 번에 한 명씩 속인다.
- Slopsquatting은 **LLM 응답**에 의존한다. 같은 질문에 같은 환각 이름이 반복되면 **수천 명이 동일한 가짜 패키지를 동시에 설치**한다.
- 연구에 따르면 오픈소스 모델 환각률은 21.7%. 대규모 코드 생성 파이프라인이 늘수록 공격 효율이 기하급수적으로 오른다.
</details>

<details>
<summary>Q3. MCP 서버를 사내에 도입할 때 가장 먼저 막아야 할 것은?</summary>

**1순위: `mcp-remote` 같은 프록시형 서버의 최신 패치.** CVE-2025-6514는 CVSS 9.6의 RCE다.
**2순위: 토큰 Passthrough 금지.** MCP 스펙이 명시적으로 금지한다. 에이전트가 받은 토큰을 다른 MCP 도구로 그대로 넘기지 않도록 프록시 레이어에서 차단.
**3순위: 도구 allowlist.** 기본은 "읽기 전용", 쓰기는 명시적 추가.
</details>

<details>
<summary>Q4. 방어자가 5대 분류 중 어디에 먼저 투자해야 하나?</summary>

업종·상황에 따라 다르지만 일반적 우선순위:
1. **E. MCP 런타임 취약점** — 가장 구체적인 CVE가 이미 나와 있고 패치로 해결 가능
2. **B. 에이전트 도구 권한 최소화** — 이미 배포된 에이전트가 있다면 즉시 감사
3. **C. 공급망(slopsquatting 포함)** — CI에 화이트리스트·사설 레지스트리 도입
4. **A. 프롬프트 인젝션 대응 프로세스** — 근본 해결은 어려우므로 샌드박스·승인 루프로 **영향 제한**
5. **D. 딥페이크 사기 방어 절차** — 기술이 아니라 **업무 프로세스** 재설계

5번은 기술팀이 아닌 **재무·임원 교육**이 더 효과적이다.
</details>

---

## 10. 다음 챕터 예고

- **03. 프런티어 모델 시대의 방어 전략** — "Mythos-Ready Security" 프레임워크, 탐지·격리·복구 자동화
- **04. AI 시스템 자체의 보안** — OWASP LLM Top 10 2025 항목별 방어 레시피 (룰 예시·코드·구성)
- **05. 에이전트 보안 실전** — MCP/툴 호출 권한 모델, 프롬프트 인젝션 완화, 샌드박스 구성

---

## 11. 참조

### OWASP
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- PDF: https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf

### 사고 분석
- GitHub MCP Prompt Injection (Simon Willison 정리): https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/
- Docker 블로그 MCP Horror Stories: https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/
- Authzed MCP Breaches Timeline: https://authzed.com/blog/timeline-mcp-breaches
- Slopsquatting Socket 분석: https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks
- Help Net Security: https://www.helpnetsecurity.com/2025/04/14/package-hallucination-slopsquatting-malicious-code/

### 딥페이크 사기
- Tookitaki 싱가포르 사례: https://www.tookitaki.com/blog/deepfake-ceo-scam-singapore-2025
- D&O Diary 통계: https://www.dandodiary.com/2025/08/articles/cyber-liability/

### MCP 취약점
- JFrog CVE-2025-6514 분석: https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/
- The Hacker News Figma MCP: https://thehackernews.com/2025/10/severe-figma-mcp-vulnerability-lets.html
- MCP 취약점 DB: https://vulnerablemcp.info/

### 공식 보안 가이드
- MCP Spec Security Best Practices (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25
- Anthropic Code Execution with MCP: https://www.anthropic.com/engineering/code-execution-with-mcp
- Microsoft Indirect Injection in MCP: https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp

---

**다음 챕터**: `03_mythos_ready_defense.md` — 고역량 공격자 가정 하의 탐지·격리·복구 자동화 프레임워크
