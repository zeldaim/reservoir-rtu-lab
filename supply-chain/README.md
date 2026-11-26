# 공급망 점검 — 서버 (단계 8의 서버 부분)

`bash supply-chain/run.sh rtu-server:locked` (이미지는 `docker build -t rtu-server:locked server/`).
[airgap-rag-lab](https://github.com/zeldaim/airgap-rag-lab)과 **같은 스크립트**를 쓴다. 방법·한계·서명 키 취급은 그쪽 [`supply-chain/README.md`](https://github.com/zeldaim/airgap-rag-lab/blob/main/supply-chain/README.md)와 같다 (비밀번호 없는 실습용 키, 투명성 로그 없음 → 서명 시각은 증명 못 함, 검증은 `cosign.pub`만 있으면 오프라인으로 됨).

## 한 일

| | 전 | 후 |
|---|---|---|
| 베이스 이미지 | `python:3.12-slim` 태그 | 다이제스트 고정 |
| nginx · cloudflared | 태그 | 다이제스트 고정 |
| 파이썬 의존성 | 최상위만 `==` | 하위까지 해시 고정(26개 · 253해시), `--require-hashes` |
| 취약점 | 몰랐다 | SBOM(CycloneDX) → grype 스캔 → 서명 |

## 발견 → 수정 → 재측정 (실제로 한 것)

스캔이 **starlette 0.41.3**(fastapi 0.115.6 가 끌고 오는 하위 의존성)에서 High 3건을 찾았다: `FileResponse` Range 헤더 O(n²) DoS, `request.form()` 한도 무시 DoS, Windows UNC 경로 SSRF(`StaticFiles`). 수정 버전은 있었지만 fastapi 가 starlette 를 묶고 있어 `fastapi 0.115.6 → 0.165.0`(starlette 1.10.0)으로 올렸다.

| | 파이썬 취약점 | High |
|---|---|---|
| fastapi 0.115.6 | 14건 | 3건 |
| fastapi 0.165.0 | **7건** | **0건** |

starlette 가 1.0 메이저로 바뀌는 큰 도약이라 **기존 테스트 26개가 그대로 통과하는지**를 확인했다(통과). 이 서버는 시연 때 cloudflared 터널로 인터넷에 노출되므로 DoS 항목은 의미가 있었다. 실제로 `FileResponse`·`StaticFiles`·`request.form()`을 쓰는지는 확인하지 않았다 — 쓰지 않는다면 이 3건은 실제 위험이 아니었을 수 있다.

## 남은 것 (숨기지 않는다)

- 전체 232건 중 212건은 베이스 이미지의 OS 패키지이고 **수정 버전이 없다.** 다이제스트로 고정했으므로 베이스 이미지 패치가 자동으로 들어오지 않는다 — 갱신은 새 다이제스트를 반영하고 로그를 다시 만든다.
- 파이썬 7건: 베이스 이미지의 `pip 25.0.1`, 그리고 **운영 이미지에 섞여 있는 `pytest 8.3.4`**(테스트 의존성을 분리하지 않았다).
- **단계 8의 나머지는 안 했다**: 펌웨어(Arduino 라이브러리) SBOM, CI 빌드 서명, 서명된 펌웨어 업데이트만 적용.
- 스캐너 심각도는 악용 가능성이 아니다. 평가하지 않았다.
- 테스트 이미지(`tests/`)에 `tools/`가 들어 있지 않아 `ai_rule_propose` 테스트는 `tools/`를 마운트해야 돌아간다(원래부터 그랬다).

실행 로그: [`run_log.txt`](run_log.txt) (재스캔 후).
