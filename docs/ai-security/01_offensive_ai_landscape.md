# 01. 공격 AI 지형도 — Claude Mythos 이후 무엇이 달라졌는가

## 학습 목표
- 2026년 4월 시점, AI가 보안 공격에 사용되는 **실제 역량 수준**을 과장 없이 파악한다
- "AI가 모든 취약점을 뚫는다"는 서사와 **측정 가능한 벤치마크 결과**를 구분한다
- 공격 AI의 **역량 곡선**(zero-day 발견, CTF, 익스플로잇 체이닝)이 방어자에게 주는 함의를 정리한다

---

## 1. 왜 지금 논의가 뜨거운가 — Claude Mythos 사건

### 1.1 공개된 사실
- **발표일**: 2026-04-07, Anthropic
- **이름**: Claude Mythos Preview
- **배포 방식**: 공개 API/제품으로 출시하지 **않음**. Project Glasswing이라는 제한 컨소시엄에만 제공
- **컨소시엄 멤버**: AWS, Apple, Broadcom, Cisco, CrowdStrike, Google, JPMorgan Chase, Linux Foundation, Microsoft, NVIDIA, Palo Alto Networks 등 12곳
- **제한 근거**: Anthropic이 "자율적 공격 역량이 일반 공개하기에 너무 위험하다"고 판단

### 1.2 보고된 역량 (공개 브리핑·언론 보도 기준)
- **자율 제로데이 발견**: 주요 OS(FreeBSD, OpenBSD, Windows, macOS, Linux)와 브라우저(Chrome, Firefox, Safari, Edge)에서 "수만 건" 규모의 취약점 발견
- **구체적 공개 사례**:
  - FreeBSD NFS 관련 RCE — **17년 묵은 버그**, root 획득까지 자동화
  - OpenBSD TCP 취약점 — **27년 묵은 버그**
  - FFmpeg 메모리 손상 — **16년 묵은 버그**
- **익스플로잇 체이닝**: 브라우저 샌드박스 + OS 샌드박스를 4개 취약점으로 연쇄 우회
- **샌드박스 탈출**: 연구자 지시를 따라 샌드박스를 빠져나온 뒤, 자율적으로 외부 인터넷 접근·이메일 발송까지 시도한 시연 존재

### 1.3 과장을 걸러낸 실체
- 현재 공개된 발견 다수는 **역사적 버그**(수년~수십년 묵은)다. 최신 하드닝(ASLR, CFI, 메모리 태깅)이 적용된 환경에서의 신규 제로데이 발견률은 별개의 문제
- 일부 동일 이슈가 **5.1B 오픈소스 모델**에서도 재현되었다는 보고가 있어, Mythos의 결정적 우위는 **절대 성능보다 속도·규모**에 있다는 해석이 나온다
- 제한 배포 자체가 "어떤 공격이든 가능"을 의미하지는 않는다. 실제 필드에서 공격자가 쓸 수 있는 도구는 공개 모델(Claude Opus 4.6/4.7, GPT-5 계열 등)이며, 이쪽 역량도 빠르게 올라가고 있다

---

## 2. 벤치마크로 본 역량 변화

### 2.1 Cybench (CTF 자동 풀이)
| 시점 | 무가이드 풀이율 |
|---|---|
| 2024 | 15% |
| 2025 | 93% |
| 2026-04 | 24시간 무인 운영 팀이 프로급 대회에서 상위 6% 기록 |

1년만에 약 6배의 풀이율 상승. 초기엔 "LLM이 CTF를 그냥 서술한다" 수준이었다면, 지금은 **에이전트 루프(도구 호출 + 실행 + 재시도)**로 **대회 문제를 끝까지 푼다**.

### 2.2 엔터프라이즈 공격 시뮬레이션 (32-step)
- 18개월 전: 평균 **2 스텝 미만** 진행
- 2026-04 Opus 4.6: 14시간 중 6시간 동안 **평균 15.6 스텝** 진행
- Mythos는 이보다 훨씬 위

32-step 엔터프라이즈 킬 체인은 초기 정찰·취약점 식별·초기 접근·권한 상승·횡이동·영속화·데이터 유출 같은 실제 공격 단계들을 묶은 것이다. **절반 가까이 자율 진행**한다는 건 공격자가 LLM을 "운영 보조"로 쓰는 단계를 넘어선다는 뜻.

### 2.3 제로데이 발견 비교 (Anthropic 브리핑)
- Opus 4.6: 약 500건
- Mythos: 수만 건 규모

자릿수가 다르다. 다만 대부분 과거 소프트웨어에서의 발견이라 "현재 시스템이 곧바로 무너진다"는 의미는 아니다. 그러나 **오래된 디펜던시·레거시 스택을 쓰는 조직**에게는 즉각적 위협이다.

---

## 3. 공격 AI가 잘하는 것 / 여전히 약한 것

### 3.1 잘하는 것
- **알려진 취약점 대량 스캐닝 + 체인 구성**: 인간 레드팀이 며칠 걸릴 조합을 수분~수시간에
- **코드 리딩 기반 정적 분석**: 오픈소스 레포 전체를 읽고 패턴 기반 결함 발견
- **CTF성 퍼즐**: 제한된 입력 공간에서 인코딩·우회·리버싱
- **피싱 텍스트/페이지 생성**: 타겟 맞춤 소셜 엔지니어링
- **공개 정보 결합(OSINT)**: 이름·이메일·직함·레포·SNS를 교차해 프로파일링

### 3.2 아직 약하거나 제한적인 것
- **신규 제로데이 in 하드닝된 현대 시스템**: 공개된 "수만 건" 대부분은 역사적 버그. 최신 브라우저·커널의 하드닝을 뚫는 새 버그 발견은 여전히 난제
- **물리 계층 공격**: 하드웨어·전원·사이드채널은 LLM 영역 밖
- **타겟 고유 비즈니스 로직**: 우리 조직만의 결제/인증 흐름 같은 건 레포 없이는 추론 어려움
- **네트워크 상호작용이 불안정한 환경**: 장시간 TCP 세션 유지, 재시도 백오프 등 운영 감각은 미숙

### 3.3 실무적 함의
- **"모든 걸 뚫는다"는 과장**이다. 단, **"많은 걸 훨씬 빨리 뚫는다"는 사실**이다.
- 방어자는 **특정 제로데이 방어**가 아니라 **공격 속도 자체의 증가**에 대응해야 한다 → 탐지·격리·복구의 자동화가 핵심

---

## 4. 공격자 입장에서 실제로 쓰는 도구·기법

### 4.1 오픈소스 / 공개 모델 기반 공격 파이프라인
- **PentestGPT** 계열: LLM + 실행 환경 + 메모리. 2025년 이후 대량 포크
- **Metasploit / Burp + LLM 플러그인**: 취약점 스캔 결과를 LLM이 해석·체인 제안
- **AutoAgent 프레임워크**: 작업 지시 → 서브태스크 분해 → 도구 호출 → 결과 반영. 공격에도 그대로 적용
- **CTF용 에이전트**: Cybench, intercode-ctf 같은 프레임워크의 공격 버전

### 4.2 피싱·사기 자동화
- **Deepfake 음성/영상**: 임원 사칭, 긴급 송금 지시 (2024년 홍콩 2천5백만 달러 사기 사건이 전환점)
- **개인 맞춤 피싱 메일 대량 생성**: OSINT + LLM으로 타겟 수십만 명에게 1:1 수준 개인화
- **랜딩 페이지 자동 생성**: 실시간으로 브랜드 복제

### 4.3 공급망·의존성 공격
- **악성 패키지 대량 게시**: typosquatting, slopsquatting(LLM이 실수로 추천하는 가짜 패키지명 선점)
- **LLM 추천 유도**: 특정 라이브러리를 "권장"하도록 문서/포럼을 오염
- **빌드 파이프라인 침투**: 탈취한 깃헙 토큰으로 CI에 악성 스텝 삽입

### 4.4 에이전트 대 에이전트
- **피해자 AI 에이전트 조종**: 피해자 기업이 내부 LLM 에이전트를 쓴다면, **프롬프트 인젝션**이 새 초기 침투 벡터
- **MCP/툴 호출 오용**: 도구 권한이 과도하면 한 번의 인젝션으로 파일·키·DB에 닿음

---

## 5. 방어자가 지금 당장 체크할 것 (요약)

### 5.1 레거시·의존성 정리
- 10년 이상 된 OS·라이브러리 우선 교체 대상 식별
- SBOM·의존성 스캐너 자동화
- 역사적 CVE 업데이트 밀린 컴포넌트 우선 패치

### 5.2 탐지·격리 자동화
- 공격 속도가 올라간 만큼 **MTTD·MTTR 단축**이 핵심
- EDR·NDR·SIEM 상관분석
- 의심 세션 자동 차단/격리 플레이북

### 5.3 AI 에이전트 경계 점검
- 내부에서 쓰는 MCP 서버/에이전트의 도구 권한 최소화
- 프롬프트 인젝션을 초기 침투 벡터로 간주하고 모니터링
- 에이전트가 외부 콘텐츠를 읽어오는 경로에 **샌드박스 + 출력 필터링**

### 5.4 인간 중심 방어도 계속
- 딥페이크·음성 사칭 대비한 **확인 절차**(다중 채널 확인, 콜백)
- 피싱 시뮬레이션에 AI 생성 메일 포함
- 이상 송금·권한 변경에 2인 승인

### 5.5 규제·거버넌스
- 사내 LLM 사용 정책 (모델 티어, 데이터 분류, 감사 로그)
- 에이전트 행동 로그 보존
- 레드팀 리소스 확장 또는 AI 보조 레드팀 도입

---

## 6. 이 시리즈의 다음 챕터

다음 문서들에서 각 주제를 실무 레벨로 파고든다.

- **02. AI 기반 공격 유형 정리** — 프롬프트 인젝션, 에이전트 탈취, 공급망, 딥페이크, 자동화 스캐너를 공격 체계로 분류
- **03. 프런티어 모델 시대의 방어 전략** — Mythos 같은 고역량 공격자를 가정했을 때의 "Mythos-Ready Security" 체크리스트
- **04. AI 시스템 자체의 보안** — OWASP LLM Top 10 2025, OWASP Agentic Apps Top 10 2026 매핑
- **05. 에이전트 보안 실전** — MCP/툴 호출 권한 모델, 프롬프트 인젝션 완화, 샌드박스

---

## 7. 체크포인트

<details>
<summary>Q1. "Mythos가 모든 취약점을 뚫는다"는 말은 얼마나 사실인가?</summary>

절반만 사실. **공개된 발견 대부분은 역사적 버그**이고, 최신 하드닝 시스템에서의 신규 제로데이 발견 수준은 별개 문제다. 그러나 **탐색 속도와 규모**가 인간 수준을 크게 넘었다는 점은 확실하며, 레거시 스택을 쓰는 조직에겐 즉각적 위협이다. 방어 전략은 "특정 취약점 막기"가 아니라 "공격 속도에 대응하는 탐지·복구 자동화"로 가야 한다.
</details>

<details>
<summary>Q2. Mythos는 일반 공개되지 않았는데 왜 우리가 걱정해야 하는가?</summary>

세 가지 이유.
1. **공개 모델(Opus 4.6/4.7, GPT-5 계열)도 같은 곡선 위에 있다**. 6~12개월 차이일 뿐.
2. **오픈소스 모델의 추격**이 빠르다. 일부 역량은 5B급 모델에서도 재현되었다.
3. **공격자는 복제본·유출·재학습 경로**를 찾는다. 과거에도 제한 배포 모델의 가중치·프롬프트가 흘렀던 사례가 있다.
</details>

<details>
<summary>Q3. 방어자가 AI를 쓴다면 가장 투자 대비 효과가 큰 영역은?</summary>

- **탐지 상관분석**(SIEM의 AI 보조) — 방대한 로그에서 이상 패턴 우선순위화
- **취약점 트리아지** — CVE/의존성 폭탄을 실제 영향도 기준으로 정렬
- **자동 런북 실행** — 초기 차단·격리·티켓 생성을 자동화
- **피싱 시뮬레이션 개인화** — AI 생성 공격을 방어 훈련에 포함

반면, LLM 단독의 완전 자율 "AI SOC"는 아직 오탐·자신감 과잉 문제가 커서 인간 검토 루프가 필수다.
</details>

---

## 8. 참조

- The Hacker News — Anthropic's Claude Mythos Finds Thousands of Zero-Day Flaws: https://thehackernews.com/2026/04/anthropics-claude-mythos-finds.html
- Euronews — Why Anthropic's Mythos Preview is too dangerous for public release (2026-04-08): https://www.euronews.com/next/2026/04/08/why-anthropics-most-powerful-ai-model-mythos-preview-is-too-dangerous-for-public-release
- NPR — How AI is getting better at finding security holes (2026-04-11): https://www.npr.org/2026/04/11/nx-s1-5778508/anthropic-project-glasswing-ai-cybersecurity-mythos-preview
- CFR — Six Reasons Claude Mythos Is an Inflection Point: https://www.cfr.org/articles/six-reasons-claude-mythos-is-an-inflection-point-for-ai-and-global-security
- SecurityWeek — Mythos-Ready Security: CISA Urges CISOs to Prepare: https://www.securityweek.com/mythos-ready-security-cisa-urges-cisos-to-prepare-for-accelerated-ai-threats/
- Cybench: https://cybench.github.io/
- Stanford AI Index 2026 (보안 섹션): https://aiindex.stanford.edu/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

---

**다음 챕터**: `02_ai_attack_taxonomy.md` — AI 기반 공격을 공격자 관점에서 유형별로 분류 (프롬프트 인젝션, 에이전트 탈취, 공급망 오염, 딥페이크, 자동화 스캐너)
