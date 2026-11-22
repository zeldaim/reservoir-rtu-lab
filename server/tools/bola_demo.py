#!/usr/bin/env python3
"""5단계 BOLA 시연 — site-b 운전원 토큰으로 site-a 사건을 조회: 취약 경로(v0) vs 고친 경로(v1).

  (서버를 LAB_VULN_BOLA=1 로 띄운 뒤 · 터널은 닫은 채로)
  LAB_VULN_BOLA=1 docker compose up -d api
  python server/tools/bola_demo.py
  docker compose up -d api        ← 끝나면 기본(꺼짐)으로 되돌리기

운전원 토큰은 server/.env 의 OPERATORS 에서 읽는다 (화면에 찍지 않음).
"""
import json
import urllib.error
import urllib.request
from pathlib import Path

ENV = Path(__file__).resolve().parents[1] / ".env"
BASE = "http://127.0.0.1:8090"


def ops():
    env = dict(l.split("=", 1) for l in ENV.read_text(encoding="utf-8").splitlines() if "=" in l and not l.startswith("#"))
    return {o["name"]: o["token"] for o in json.loads(env["OPERATORS"])}


def get(path, tok):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def main():
    t = ops()
    a, b = t["operator-a"], t["operator-b"]
    rows = []
    for label, path in [("취약 (v0, 권한 검사 없음)", "/api/v0/sites/site-a/events?minutes=1440"),
                        ("고친 쪽 (v1, 사이트 담당 확인)", "/api/v1/sites/site-a/events?minutes=1440")]:
        st, body = get(path, b)
        n = len(body["events"]) if body else 0
        sample = body["events"][0]["type"] + " " + body["events"][0]["detail"] if n else "-"
        rows.append((label, st, n, sample))
    print("site-b 운전원이 주소의 site 만 site-a 로 바꿔 조회:")
    print(f"{'경로':<28} {'상태':>4} {'새어 나간 사건':>12}  예시")
    for label, st, n, sample in rows:
        print(f"{label:<28} {st:>4} {n:>12}  {sample}")
    st, det = get("/api/v1/sites/site-a/detections?minutes=10", a)
    print("\nsite-a 운전원이 보는 탐지 기록 (최근 10분):")
    for d in (det or {}).get("detections", []):
        if d["kind"] in ("BOLA_LEAK", "CROSS_SITE_DENIED"):
            print(f"  {d['kind']:<18} {d['detail']}")


if __name__ == "__main__":
    main()
