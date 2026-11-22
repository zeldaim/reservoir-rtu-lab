# reservoir-rtu-lab — 무인 배수지 원격감시 장치(RTU) 보안 관제

ESP32 원격감시 장치(Wokwi 시뮬레이터)와, 그 장치를 지키는 관제 서버.
**출입통제(물리 침입) + 수위·밸브 공정(사이버 조작)** 을 한 장치에서 다루고, 공격 · 방어를 측정한다.
임베디드프로그래밍(아두이노) 과제 + 기반시설(OT) 보안 포트폴리오 — 성적이 나오기 전까지 비공개.

```
현장 RTU (ESP32 · FreeRTOS)                       관제 서버 (PC · Docker)
 출입: 조작반 PIN · 레이트 리밋 잠금 · PIR 침입   ──▶   nginx 레이트 리밋 · 차단 목록
 공정: 수위(초음파) · 밸브(서보) · 펌프 자동 제어        API (사이트 토큰) — BOLA 시연·수정
       넘침 · 고갈 · 급변 경보                           탐지: 룰(명세에서 자동 생성) + ML
 사건 기록 (HMAC 서명) · 서명된 업데이트만 적용          AI 사고 리포트 · 자동 대응
 LCD 에 요약 · 부저                               ◀──   (출발지 차단 · 현장 안전 모드 · 알림)
```

## 부품 → 역할

| 수업 부품 | 역할 | 수업 |
|---|---|---|
| 버튼 4개 + LCD | 현장 조작반 · 운전원 PIN | 4 · 12주차 |
| 서보 ×2 | 출입문 · 유출 밸브 | 8주차 |
| 초음파 | 수위계 (탱크 200cm) | 13주차 |
| PIR | 침입 감지 | — |
| LED (초록 · 빨강 · 파랑) | 열림 · 거부 · 유입 펌프 | 2주차 |
| 부저 | 출입 · 공정 경보 | 5주차 |
| 온습도 DHT11 (Wokwi: DHT22) | 설비실 온습도 — 40°C↑ 과열 · 85%↑ 결로/침수 | 11주차 |
| LM35 (Wokwi: 가변저항) | 펌프 모터 온도 — 70°C↑ 펌프 강제 정지(인터록), 60°C↓ 해제 | 9 · 11주차 |

**시뮬레이터 대체 부품:** Wokwi 에 없는 부품은 같은 방식으로 흉내 낸다.

| 실물 | Wokwi | 다른 점 |
|---|---|---|
| DHT11 | DHT22 | 같은 계열 · 같은 라이브러리. 코드 `DHT_TYPE` 한 줄 (DHT11 은 정밀도 낮고 1초마다 읽기 가능) |
| LM35 | 가변저항 (GPIO34) | 출력 전압을 손으로 만든다. 계산식(1°C = 10mV)은 실물과 같음 |
| 시리얼 | 사건 기록 · 측정값 | 10주차 |

## 단계

| 단계 | 내용 | 상태 |
|---|---|---|
| 1 | 출입통제 본체 (`firmware/doorlock`): PIN · 레이트 리밋 잠금 · 배회 감지 · 사건 기록 | 코드 완료 · 출입통제 동작은 RTU 안에서 Wokwi 확인(PIN · 5회 잠금 · INTRUSION/MOTION), 단독 `doorlock` 스케치는 따로 안 돌림 |
| 2 | **RTU + FreeRTOS 작업 분리** (`firmware/rtu`): 공정 제어 추가, 통신 중에도 제어 · 입력이 멈추지 않게. 분리 전 · 후 간격 측정 (`NET_IN_LOOP`) | Wokwi 컴파일 · 실행 완료(2026-11-22) — DHT 코어 0 이동(입력 간격 120~197 → 11~12 ms), vTaskDelayUntil(공정 주기 261 → 200 ms). `NET_IN_LOOP` 0/1 비교 표는 아직 |
| 3 | 관제 서버 + 사건 전송(HMAC 서명) + AI 사고 리포트 (AI API 키는 서버에만) | 서버 완료(가짜 장치로 200 · 같은 번호 다시 보내기 409 확인) · 펌웨어 실제 전송 코드 완료 · **Wokwi ↔ 서버 연결 미확인** |
| 4 | 서버 ML — 레이트 리밋 아래 느린 무차별 대입 · 공정값 이상(설정값 조작) 탐지, 레이트 리밋과 비교 표. **정상 패턴은 실제 K-water 공공데이터로 학습** — 데이터 계층은 별도 공개 레포 [aquaflow-pipeline](https://github.com/zeldaim/aquaflow-pipeline) (수집 → ORC → DuckDB 얇은 버전) · 센서 값 재생 · 저장 전 품질 검증(조작 값 · 학습 데이터 오염 방지) | |
| 5 | API 보안 — 사이트 A 계정으로 사이트 B 조회 · 제어(BOLA) 시연 → 수정 → 탐지 · 원격 명령 레이트 리밋 | |
| 6 | API-BOM (명세 + 관측 트래픽 → API 목록 · 숨은 API) · 명세에서 탐지 룰 자동 생성 · CI 룰 시험 | |
| 7 | 자동 대응 — 경보 → 플레이북 (출발지 차단 · 현장 안전 모드: 원격 명령 거부 · 알림) | |
| 8 | 공급망 — 라이브러리 버전 고정 · 펌웨어/서버 SBOM · 취약점 검사 · CI 빌드 서명 · 서명된 업데이트만 적용 | |
| 9 | 점검 보고서 자동화 — KISA 주요정보통신기반시설 취약점 분석·평가 가이드를 기준으로 서버 · 장치 점검 → 양호/취약/해당없음 · 근거 · 조치 보고서 (구조는 기존 `kisa-windows-hardening-lab` 의 취약 조성 → 점검 → 하드닝 → 재점검을 재사용, 서버는 Unix 항목) | |
| 10 | (선택) 기기 ML — 조작반 입력 리듬으로 운전원 판별 (TinyML) · Modbus TCP | |
| 11 | 개발 문서(PDF) · 시연 영상(5~10분) · 스마트그리드(AMI) 적용 절 | |

## 실행 (단계 1~2)
- **Wokwi:** wokwi.com → New Project → ESP32 → `firmware/rtu/` 의 `rtu.ino`(→ sketch.ino) · `diagram.json` · `libraries.txt` 붙여 넣기 → ▶
  - 수위: 초음파 센서 클릭 → 거리 슬라이더 (거리가 짧을수록 수위가 높음. 30cm = 수위 170cm → 밸브 열림)
  - 침입: PIR 클릭 → 움직임 시뮬레이션 (PIN 인증 없이 → `INTRUSION`)
  - 설비실: DHT22 클릭 → 온도 40°C↑ `ENV_HOT` · 습도 85%↑ `ENV_HUMID`
  - 모터 과열: 가변저항을 돌려 0.7V(=70°C) 넘기면 `INTERLOCK` · LCD 에 `PIL`. **시작 전 가변저항을 낮게** (가운데면 약 165°C 라 바로 인터록)
  - 시리얼: `log` = 사고 기록 · `stat` = 작업별 간격 · 스택 여유
  - 비교: 코드 맨 위 `#define NET_IN_LOOP 0` 을 `1` 로 바꾸면 1단계 구조(전송 중 멈춤)
- **컴파일 (로컬):** `arduino-cli compile --fqbn esp32:esp32:esp32 firmware/rtu`

## 실행 (단계 3 — 장치 → 서버)
1. 비밀값 (처음 한 번): `python server/tools/provision.py` → `server/.env` · `firmware/rtu/secrets.h` (둘 다 git 에 안 올라감)
2. 서버: `cd server && docker compose up -d --build` → `curl http://127.0.0.1:8090/healthz`
3. 터널 (시험할 때만): `docker compose --profile tunnel up -d tunnel` → `docker compose logs tunnel | grep trycloudflare` 의 주소를 `secrets.h` 의 `SERVER_URL` 에
4. Wokwi: 기존 탭에 **`secrets.h` · `ca_roots.h` 탭 추가** → ▶. 시리얼에 `NET wifi 연결` → `NET 보냄 N건 status=200 …ms`
   - `secrets.h` 탭이 없으면 2단계처럼 가짜 전송 (`STAT … net=fake`)
   - **`secrets.h` 를 넣은 채로 Wokwi 프로젝트를 저장하지 않는다** (Wokwi 프로젝트는 링크로 남에게 보일 수 있음). 저장했다면 `provision.py --force` 로 새로 만든다
5. 확인: `docker compose logs api` — 거절은 이유가 로그에만 남는다 (`bad_signature` · `stale_timestamp` · `replayed_seq` …)
6. 다 쓰면 터널 닫기: `docker compose --profile tunnel stop tunnel`

장치 쪽 동작: 사건을 0.3초 모아 최대 10건씩 보냄 · 실패(401 · 429 · 5xx · 연결)는 그 묶음을 들고 1→2→…30초 간격으로 다시 · 다시 보내도 안 되는 거절(400 · 403 · 409 · 413)은 버림(장치 `log` 에는 남음) · 보낼 때마다 새 번호 · 새 시각 · 새 서명. 서버 인증서는 `ca_roots.h` 의 루트 CA 로 확인 (`setInsecure` 안 씀, 다시 만들기 `python server/tools/make_ca_roots.py`).

## 알려 둘 제약
- 이 PC 는 Windows 애플리케이션 제어 정책이 ESP32 컴파일러를 막는다 — 컴파일 · 실행은 Wokwi 에서 한다 (2026-11-22 실행 확인, 측정값은 `docs/개발문서_초안.md` 3.2).
- Wokwi 웹의 가상 Wi-Fi 는 **인터넷으로만** 나간다. 내 PC(localhost)로 들어오는 Private Gateway 는 유료라, 3단계 서버 연결 방식(터널 등)은 따로 정한다.
- Wokwi 공개 게이트웨이는 트래픽을 모니터링한다 — 실제 비밀값은 보내지 않는다.
- 실제 PLC · 산업 프로토콜이 아닌 **흉내**다. 공정 제어는 히스테리시스 한 개짜리 단순 제어.
