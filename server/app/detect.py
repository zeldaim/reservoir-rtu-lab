"""서버 탐지 (4단계 a) — 장치 레이트 리밋 아래로 천천히 하는 PIN 무차별 대입.

장치는 "60초에 5번 틀리면 30초 잠금"만 본다(펌웨어 FAIL_LIMIT · FAIL_WINDOW). 그래서 1분에 4번씩 계속 시도하면
장치는 한 번도 잠기지 않는다. 서버는 사건을 오래 모아 보므로 긴 창으로 센다:

  30분에 실패 10번 이상  — 정상 운전원의 오타(가끔 1~3번)와 구분되는 수
  24시간에 실패 20번 이상 — 더 느린 시도(5분에 1번 등)

ML 이 아니라 규칙이다: "몇 분에 몇 번"으로 말이 되는 공격이라 규칙이 정확하고, 왜 잡혔는지 설명할 수 있다.
기준값은 정상 운영 기록이 쌓이면 사이트별 평소 실패 수로 다시 정한다 (지금은 시연용 가정값).
"""
from __future__ import annotations

WINDOWS = [(30 * 60, 10, "30분"), (24 * 3600, 20, "24시간")]   # (창 길이 초, 기준 실패 수, 이름)
DEDUPE_S = 30 * 60                                           # 같은 창의 탐지는 30분에 한 번만 남김


def event_time(e: dict) -> float:
    """장치 시각(NTP 로 맞춘 유닉스 초)이 있으면 그걸, 없으면(부팅 뒤 초) 서버가 받은 시각."""
    t = e.get("device_t")
    try:
        if t is not None and int(t) >= 1_000_000_000:
            return float(t)
    except (TypeError, ValueError):
        pass
    return float(e.get("received_at") or 0)


def slow_bruteforce(events: list[dict], now: float) -> list[dict]:
    """창마다 PIN 실패 수를 세서 기준을 넘으면 탐지. device_lockouts = 그 창에서 장치가 스스로 잠근 횟수
    (0 이면 장치 레이트 리밋을 피한 공격)."""
    out = []
    for span, limit, name in WINDOWS:
        inwin = [e for e in events if now - span <= event_time(e) <= now + 300]
        fails = sum(1 for e in inwin if e.get("type") == "FAIL")
        if fails < limit:
            continue
        locks = sum(1 for e in inwin if e.get("type") == "LOCKOUT")
        evaded = " — 장치 잠금 없이 (레이트 리밋 아래)" if locks == 0 else ""
        out.append({"kind": "SLOW_BRUTEFORCE", "window": name, "fails": fails, "limit": limit,
                    "device_lockouts": locks,
                    "detail": f"{name} PIN 실패 {fails}회 (기준 {limit}) · 장치 잠금 {locks}회{evaded}"})
    return out
