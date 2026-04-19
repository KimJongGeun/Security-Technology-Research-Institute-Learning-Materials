# 04. OWASP LLM Top 10:2025 항목별 방어 레시피

## 학습 목표
- OWASP LLM Top 10:2025의 10개 항목 각각에 대해 **실제 배포 가능한 방어 도구·기법**을 파악한다
- 매니지드 서비스(Azure / Google / Cloudflare)와 오픈소스 대안을 함께 알고, 사내 환경에서 취사선택할 수 있다
- 2025~2026에 신규로 추가된 LLM07(System Prompt Leakage) / LLM08(Vector and Embedding Weaknesses) / LLM10(Unbounded Consumption)의 구체 방어 방법을 정리한다

> 본 문서는 제품 추천이 아니라 **공식 문서·오픈소스 레포·표준 스펙이 존재하는 도구만** 나열한다. 실제 도입은 각 조직의 망분리·규제·비용 조건에 따라 다시 검증해야 한다.

> 각 항목 링크는 OWASP GenAI 프로젝트 공식(https://genai.owasp.org/) 기준이다.

---

## 매핑 개요

| ID | 이름 | 주 방어 계층 | 대표 도구 |
|---|---|---|---|
| LLM01 | Prompt Injection | 입력 전처리 + 런타임 가드 | Azure Prompt Shields, LlamaFirewall |
| LLM02 | Sensitive Information Disclosure | 입출력 마스킹 | Presidio, Google SDP |
| LLM03 | Supply Chain | 빌드·배포 무결성 | CycloneDX ML-BOM, Sigstore model-transparency |
| LLM04 | Data and Model Poisoning | 데이터 무결성 + 접근통제 | MITRE ATLAS Mitigations, Croissant |
| LLM05 | Improper Output Handling | 렌더링 경로 필터 | DOMPurify, bleach, Pydantic Output Parser |
| LLM06 | Excessive Agency | 도구 권한 + 인간 승인 | Anthropic Computer Use 가이드, OpenAI function-calling |
| LLM07 | System Prompt Leakage (신규) | 권한 모델 외부화 | OWASP 공식 권고 |
| LLM08 | Vector and Embedding Weaknesses (신규) | 멀티테넌시 격리 | Pinecone namespaces, pgvector + Postgres RLS |
| LLM09 | Misinformation | Citation 강제 + 평가 | LlamaIndex CitationQueryEngine, Ragas, TruLens |
| LLM10 | Unbounded Consumption | Rate/budget 게이트웨이 | Cloudflare AI Gateway, LiteLLM Proxy |

---

## LLM01 — Prompt Injection

### 왜 항상 1위인가
OWASP 2023·2024·2025 모두 1위. 2025판은 **직접 / 간접 인젝션**을 명시 구분하고, 간접 인젝션(외부 콘텐츠에 숨긴 지시)을 주 위협으로 강조.

### 매니지드
- **Microsoft Azure AI Content Safety — Prompt Shields**
  - 직접·간접 인젝션 탐지, Azure OpenAI 파이프라인에 플러그인
  - 문서: https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection

### 오픈소스
- **Meta LlamaFirewall (PurpleLlama)**
  - 2025년 공개. `PromptGuard 2`(인젝션 탐지) + `AlignmentCheck`(목표 이탈 감지) + `CodeShield`(코드 출력 안전 검증) 통합
  - 레포: https://github.com/meta-llama/PurpleLlama
- **NVIDIA NeMo Guardrails**
  - Colang DSL로 대화 흐름 제약, 입력·출력 필터·도구 호출 정책
  - 레포: https://github.com/NVIDIA/NeMo-Guardrails
- **Protect AI Rebuff**
  - 캐노리 토큰·벡터 기반 유사도 검사·LLM 검사 4단계
  - 레포: https://github.com/protectai/rebuff

### 방어 설계 기법
- **Spotlighting** (arXiv:2403.14720) — delimiting / datamarking / encoding 3기법으로 간접 인젝션 성공률 50%+ → 2% 미만
  - 논문: https://arxiv.org/abs/2403.14720
- **신뢰 등급 주입**: 프롬프트 구성 단계에서 외부 입력을 `<untrusted_source>…</untrusted_source>` 같은 명시 토큰으로 감싸기
- **도구 호출 샌드박스**: 인젝션이 성공해도 영향 범위를 제한

### 최소 기준
1. 외부 콘텐츠를 읽는 모든 에이전트에 **간접 인젝션 가드 1개 이상** (매니지드 or OS)
2. 결정적 행위(쓰기·송금·삭제)는 **인간 승인 루프**
3. 인젝션 성공 시나리오를 **레드팀 회귀 테스트**로 주 1회 이상

---

## LLM02 — Sensitive Information Disclosure

### 포인트
2025판에서 **6위 → 2위로 상승**. 원인은 LLM 앱이 RAG·툴 호출로 사내 데이터에 접근하는 빈도 증가.

### 입출력 마스킹 도구
- **Microsoft Presidio**
  - PII 탐지·가명처리·복원 전용 오픈소스
  - 한국어 엔티티는 SpaCy·정규식 커스터마이즈 필요
  - 레포: https://github.com/microsoft/presidio
- **Google Cloud Sensitive Data Protection (구 DLP API)**
  - `deidentify` 엔드포인트로 입력 마스킹, `reidentify`로 복원
  - 문서: https://cloud.google.com/sensitive-data-protection/docs

### 응답 모더레이션
- **OpenAI Moderation API** — `omni-moderation-latest` (2024-09)
  - 문서: https://platform.openai.com/docs/guides/moderation
  - 2025~2026 메이저 업데이트는 이 문서 작성 시점에 확인된 공식 자료 없음

### 파이프라인 위치
1. **사용자 입력 단계**: PII 토큰화 후 LLM에게 전달 (LLM은 token만 봄)
2. **LLM 응답 단계**: 응답에서 token → 원본 복원 또는 마스킹 유지
3. **로그·캐시 저장 단계**: 마스킹된 형태로만 보존

### 최소 기준
1. 사용자 입력의 **주민번호·카드번호·계좌번호·이메일·전화번호** 패턴 탐지
2. LLM 응답에 **시크릿 토큰 패턴**(`ghp_*`, `sk-*`, `AKIA*`, `xox[bp]-*`) 거부 또는 마스킹
3. 마스킹된 원본은 **감사 로그에만** 복원 권한 부여

---

## LLM03 — Supply Chain

### 포인트
2025판에서 5위 → 3위로 상승. 모델 가중치·데이터셋·플러그인·확장 도구까지 포괄.

### 모델·데이터 무결성
- **CycloneDX ML-BOM** (v1.5+에서 ML 컴포넌트 공식 지원)
  - SBOM의 ML 확장. 학습 데이터셋·하이퍼파라미터·모델 카드·에너지 소비까지 기술 가능
  - 문서: https://cyclonedx.org/capabilities/mlbom/
- **Hugging Face safetensors** — pickle 대신 안전한 텐서 포맷 강제
  - 레포: https://github.com/huggingface/safetensors
- **picklescan** — pickle 기반 모델 파일의 악성 코드 정적 탐지
  - 레포: https://github.com/mmaitre314/picklescan

### 서명·출처 증명
- **Sigstore Model Transparency**
  - 모델 가중치 서명·검증. Rekor 투명성 로그에 기록
  - 레포: https://github.com/sigstore/model-transparency
- **in-toto attestation** — 빌드 파이프라인 전 단계 증명
  - 레포: https://github.com/in-toto/attestation

### 최소 기준
1. 외부에서 다운받은 모델은 **safetensors만 허용**, pickle 기반은 picklescan 통과 후에만
2. 프로덕션 서비스에 들어가는 모델 가중치는 **Sigstore 서명 검증**
3. ML-BOM을 빌드 파이프라인에서 자동 생성하고 배포본과 함께 보관

---

## LLM04 — Data and Model Poisoning

### 포인트
학습 데이터·파인튜닝 데이터·RAG 인덱스에 악성 샘플이 섞여 모델 동작을 왜곡.

### 완화 매핑
- **MITRE ATLAS Mitigations**
  - `AML.M0005 Control Access to ML Models`
  - `AML.M0014 Verify ML Artifacts`
  - 페이지: https://atlas.mitre.org/mitigations/

### 데이터 표준
- **Croissant 스키마** (MLCommons) — 데이터셋 메타데이터 표준화
  - 레포: https://github.com/mlcommons/croissant
- 데이터셋 해시·서명은 Sigstore/in-toto를 재활용 (전용 "공식 표준"은 이 문서 작성 시점에 확인된 자료 없음)

### 실무 방어 루틴
1. 학습·파인튜닝 데이터 출처별 **해시 기록**, 체인지 로그 유지
2. RAG 인덱스 업데이트 시 **변경 문서만 서명 검증**
3. 외부 사용자 기여 데이터는 **별도 파티션**에서 튜닝·평가 후에만 메인 모델에 반영
4. `AML.M0005` 기반 접근 통제: 누가 언제 어떤 데이터로 어떤 모델을 훈련했는지 감사 가능

---

## LLM05 — Improper Output Handling

### 포인트
LLM 응답을 **일반 사용자 입력처럼 취급**해야 한다. 응답을 그대로 HTML로 렌더하면 저장형 XSS, 그대로 SQL로 쓰면 SQL 인젝션.

### 렌더링 필터
- **DOMPurify** (JavaScript): HTML/SVG/MathML 정화
  - 레포: https://github.com/cure53/DOMPurify
- **bleach** (Python): HTML whitelist 기반 필터
  - 레포: https://github.com/mozilla/bleach

### 구조화 응답 강제
- **LangChain `PydanticOutputParser` / `StructuredOutputParser`**
  - 응답을 JSON/스키마에 맞춰 파싱, 파싱 실패 시 재시도·거부
  - 문서: https://python.langchain.com/docs/concepts/output_parsers/

### 레시피
- 챗봇 응답 → 마크다운 렌더링 시: **sanitize-html 또는 DOMPurify 적용**
- LLM이 SQL 생성 → **화이트리스트된 명령어만 실행**, prepared statement 강제
- LLM이 쉘 명령 생성 → **절대 shell=True 금지**, argv 배열로만

### OWASP 공식 치트시트
- https://genai.owasp.org/llmrisk/llm05-improper-output-handling/

---

## LLM06 — Excessive Agency

### 포인트
에이전트에게 필요 이상의 도구·권한·자율성을 주는 것. 02 챕터의 Supabase Cursor 토큰 유출이 대표 사례.

### 벤더 공식 가이드
- **Anthropic Computer Use**
  - 격리된 VM, 민감 계정 분리, 허용 도메인 allowlist, 프롬프트 인젝션 대응
  - 문서: https://docs.anthropic.com/en/docs/build-with-claude/computer-use
- **OpenAI function calling / Assistants**
  - 도구 단위 권한, tool_choice 제어, human-in-the-loop 권고
  - 문서: https://platform.openai.com/docs/guides/function-calling

### 방어 원칙
1. **도구 allowlist**: 기본은 RO, 쓰기·삭제·외부 전송은 명시 추가
2. **세션당 호출 제한**: 한 태스크에서 호출 가능한 도구 수·빈도 상한
3. **인간 승인 게이트**: `git push`, `rm`, 송금, 권한 변경 등은 반드시 확인
4. **감사 로그**: 모든 도구 호출 arg·결과 기록

### OWASP 공식
- https://genai.owasp.org/llmrisk/llm06-excessive-agency/

---

## LLM07 — System Prompt Leakage (2025 신규)

### 왜 추가됐나
개발자가 시스템 프롬프트에 **비밀번호·내부 API 키·행동 규칙**을 넣고 "유출되지 않을 것"이라고 가정하는 패턴이 사고로 이어졌다. OWASP는 **"시스템 프롬프트를 보안 경계(security boundary)로 사용하지 말 것"**을 공식 권고.

### 공식 문서
- https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/

### 올바른 패턴
1. 민감 정보는 **프롬프트 밖** (환경변수, secret manager)
2. 권한은 **시스템 프롬프트가 아닌 API 레이어**에서 강제
3. 프롬프트에 있는 "역할 지시" 자체가 유출돼도 **기능·보안 영향 없도록** 설계
4. 유출 탐지는 정기적 레드팀 테스트로만 가능 — 프롬프트 엔지니어링으론 근본 방어 불가

### 안티패턴 (피해야 할 것)
- "당신은 관리자 비밀번호 XXXX을 절대 공개하지 마세요" ← 프롬프트가 유출되면 비번도 함께 유출
- "당신은 다음 사용자만 서비스하세요: 허용 목록 …" ← 권한은 API에서 체크해야

### 사례
2025~2026 실제 유출 사례 중 **벤더 공식 포스트모템**으로 기록된 1차 자료는 이 문서 작성 시점에 확인되지 않음. 커뮤니티 스크린샷 유통은 다수 있으나 근거로 쓰지 않는다.

---

## LLM08 — Vector and Embedding Weaknesses (2025 신규)

### 왜 추가됐나
RAG가 일반화되면서 벡터 DB 자체가 공격면이 됨. **멀티테넌시 격리 실패**로 A사 질문이 B사 문서로 답변되는 사고 가능.

### 벡터 DB 공식 기능
- **Pinecone Namespaces**: 테넌트별 논리 분리
  - 문서: https://docs.pinecone.io/guides/indexes/use-namespaces
- **Weaviate Multi-tenancy**: 테넌트 단위 격리 공식 지원
  - 문서: https://weaviate.io/developers/weaviate/manage-data/multi-tenancy
- **pgvector + Postgres Row-Level Security (RLS)**
  - 레포: https://github.com/pgvector/pgvector
  - RLS 공식: https://www.postgresql.org/docs/current/ddl-rowsecurity.html

### 레시피
1. 테넌트마다 **namespace / collection / RLS policy** 중 하나 강제
2. 쿼리 시 **메타데이터 필터가 누락되면 거부** (앱 레이어에서 검증)
3. 문서 ID는 **테넌트 prefix** 포함 → 크로스-테넌트 참조 탐지
4. 벡터 DB 접근 로그를 SIEM에 연동

### OWASP 공식
- https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/

---

## LLM09 — Misinformation

### 포인트
2023판의 "Overreliance"에서 2025판은 **Misinformation**(허위 정보 생성·전파)으로 재정의. 법률·의료·금융 도메인에서 특히 위험.

### 기법 1 — Citation 강제
- **LlamaIndex CitationQueryEngine**
  - 모든 응답에 source 문서 ID 포함 강제
  - 문서: https://docs.llamaindex.ai/en/stable/examples/query_engine/citation_query_engine/
- 시스템 프롬프트에 `"각 주장 뒤에 [source: doc_id] 태그 필수, 없으면 답변 거부"` 명시
- 출력 스키마에 `citations: list[str]` 필수 필드

### 기법 2 — 평가 루프
- **Ragas**: RAG 품질 평가 오픈소스 (faithfulness, answer relevance, context precision)
  - 레포: https://github.com/explodinggradients/ragas
- **TruLens**: LLM 앱 관측·평가 (groundedness, feedback)
  - 레포: https://github.com/truera/trulens

### 레시피
1. 프로덕션 트래픽 샘플 1%를 매일 Ragas/TruLens로 평가
2. **faithfulness < 임계값**이면 알림
3. 모델·프롬프트 변경 시 회귀 테스트셋 자동 재실행

---

## LLM10 — Unbounded Consumption

### 포인트
2023판의 `Model DoS`가 **2025판에서 확장**. 토큰·비용·쿼리·추출 공격까지 포괄.

### 매니지드 게이트웨이
- **Cloudflare AI Gateway**
  - 요청/토큰 단위 rate limit, 캐싱, 비용 가시성, 로깅
  - 문서: https://developers.cloudflare.com/ai-gateway/

### 오픈소스 게이트웨이
- **LiteLLM Proxy**
  - 100+ 모델 통합, 키별 budget/TPM/RPM 제한, 팀별 quota
  - 문서: https://docs.litellm.ai/docs/proxy/users

### 탐지·방어 레시피
1. 사용자/API 키별 **sliding window 토큰 카운터**
2. 평소 대비 **10σ 초과 스파이크** → 자동 비활성 + 알림
3. 프롬프트 길이 vs 응답 길이 비율 이상 → **모델 추출 공격** 의심
4. 캐시 레이어(Redis)로 동일 프롬프트 재호출 비용 0원
5. `max_tokens`, `stop`, `timeout` 기본값 모든 경로에 강제

### OWASP 공식
- https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/

---

## 통합 아키텍처 — 최소 구성 예시

모든 항목을 한 번에 반영한 최소 구성 다이어그램.

```
 [사용자]
    │
    ▼
 [AI Gateway]  ← LLM10: rate limit, 비용 캡, 로깅
    │
    ▼
 [입력 Sanitizer]  ← LLM02: Presidio 마스킹
    │          ← LLM01: Prompt Shields/LlamaFirewall 인젝션 탐지
    ▼
 [LLM 호출]  ← 모델 가중치는 Sigstore 검증 (LLM03)
    │
    ▼
 [응답 Parser/Filter]  ← LLM05: Pydantic + DOMPurify
    │                   ← LLM09: citation 필수 검증
    │                   ← LLM02: 시크릿 마스킹
    ▼
 [출력]  → 감사 로그 (마스킹된 형태)
          → Ragas/TruLens 1% 샘플 평가

 RAG 질의:
   [질문] → [테넌트 필터 강제 (LLM08)] → 벡터 DB (네임스페이스/RLS) → 답변

 에이전트 도구 호출 (LLM06):
   [계획] → [도구 allowlist 검증] → [호출] → [감사 로그]
                                         ↓
                                  [인간 승인 게이트] (쓰기·파괴 도구만)
```

---

## 체크포인트

<details>
<summary>Q1. "모든 항목에 도구 하나씩 도입"이 현실적인가?</summary>

아니다. 우선순위 기준:
1. **LLM10**(비용 폭주)과 **LLM02**(PII 유출)가 즉시 금전·규제 피해. 1순위.
2. **LLM01**(프롬프트 인젝션)은 에이전트가 외부 콘텐츠를 읽는 시스템만 도입.
3. **LLM08**(RAG 멀티테넌시)은 멀티테넌트 제품을 운영할 때만.
4. **LLM03·LLM04**(공급망·데이터 포이즈닝)는 자체 모델 학습/파인튜닝 하는 경우에만.
5. 나머지는 1~4를 먼저 갖춘 뒤 순차 도입.
</details>

<details>
<summary>Q2. 매니지드(Azure/Cloudflare) vs 오픈소스 어느 쪽이 유리한가?</summary>

- **매니지드 유리**: PoC 단계, 소규모 팀, 망분리 없음
- **오픈소스 유리**: 데이터가 외부로 나가면 안 되는 환경(금융·의료·공공), 대규모로 비용 예민
- 실무는 대개 **혼합**: 게이트웨이·rate limit은 매니지드로, PII·프롬프트 인젝션은 오픈소스 커스터마이즈
</details>

<details>
<summary>Q3. LLM07을 "프롬프트 엔지니어링"으로만 대응하면 왜 실패하는가?</summary>

프롬프트는 평문으로 모델에 들어가고, 어떤 입력이든 모델의 문맥에 "단지 이전 대화"로 보인다. 즉, 공격자가 모델을 설득해 "앞서 시스템이 준 규칙을 다시 말해달라"고 하면 모델이 그걸 출력하지 않을 보장이 없다. 따라서 **권한·비밀은 프롬프트 밖**에 두는 게 근본 방어. "유출 방지 문구"는 레이어드 디펜스의 하위 장치 정도로만 쓴다.
</details>

---

## 참조

### OWASP 공식
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- LLM05 치트시트: https://genai.owasp.org/llmrisk/llm05-improper-output-handling/
- LLM06: https://genai.owasp.org/llmrisk/llm06-excessive-agency/
- LLM07: https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/
- LLM08: https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- LLM10: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/

### LLM01 방어 도구
- Microsoft Prompt Shields: https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection
- Spotlighting 논문: https://arxiv.org/abs/2403.14720
- Meta LlamaFirewall (PurpleLlama): https://github.com/meta-llama/PurpleLlama
- NVIDIA NeMo Guardrails: https://github.com/NVIDIA/NeMo-Guardrails
- Rebuff: https://github.com/protectai/rebuff

### LLM02·05 방어 도구
- Presidio: https://github.com/microsoft/presidio
- Google Sensitive Data Protection: https://cloud.google.com/sensitive-data-protection/docs
- OpenAI Moderation: https://platform.openai.com/docs/guides/moderation
- DOMPurify: https://github.com/cure53/DOMPurify
- bleach: https://github.com/mozilla/bleach
- LangChain Output Parsers: https://python.langchain.com/docs/concepts/output_parsers/

### LLM03·04 공급망·데이터 무결성
- CycloneDX ML-BOM: https://cyclonedx.org/capabilities/mlbom/
- safetensors: https://github.com/huggingface/safetensors
- picklescan: https://github.com/mmaitre314/picklescan
- Sigstore Model Transparency: https://github.com/sigstore/model-transparency
- in-toto attestation: https://github.com/in-toto/attestation
- MLCommons Croissant: https://github.com/mlcommons/croissant
- MITRE ATLAS Mitigations: https://atlas.mitre.org/mitigations/

### LLM06 에이전트 권한
- Anthropic Computer Use: https://docs.anthropic.com/en/docs/build-with-claude/computer-use
- OpenAI function calling: https://platform.openai.com/docs/guides/function-calling

### LLM08 벡터 DB
- Pinecone Namespaces: https://docs.pinecone.io/guides/indexes/use-namespaces
- Weaviate Multi-tenancy: https://weaviate.io/developers/weaviate/manage-data/multi-tenancy
- pgvector: https://github.com/pgvector/pgvector
- Postgres RLS: https://www.postgresql.org/docs/current/ddl-rowsecurity.html

### LLM09 평가·citation
- LlamaIndex CitationQueryEngine: https://docs.llamaindex.ai/en/stable/examples/query_engine/citation_query_engine/
- Ragas: https://github.com/explodinggradients/ragas
- TruLens: https://github.com/truera/trulens

### LLM10 게이트웨이
- Cloudflare AI Gateway: https://developers.cloudflare.com/ai-gateway/
- LiteLLM Proxy: https://docs.litellm.ai/docs/proxy/users

---

**다음 챕터**: `05_agent_security_playbook.md` — MCP/툴 호출 권한 모델, 프롬프트 인젝션 완화 실전 구현, 샌드박스 구성
