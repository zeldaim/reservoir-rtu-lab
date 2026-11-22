#!/usr/bin/env python3
"""장치 · 운전원 비밀값 만들기 — 처음 한 번.

  python server/tools/provision.py            → server/.env · firmware/rtu/secrets.h (둘 다 git 에 안 올라감)

이미 있으면 덮어쓰지 않는다 (--force 로만). 비밀값은 secrets 모듈(암호학적 난수)로 만든다.
ANTHROPIC_API_KEY 는 직접 .env 에 넣는다 (이 스크립트는 건드리지 않음).
"""
import argparse
import json
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "server" / ".env"
SECRETS_H = ROOT / "firmware" / "rtu" / "secrets.h"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--site", default="site-a")
    a = ap.parse_args()
    if (ENV.exists() or SECRETS_H.exists()) and not a.force:
        raise SystemExit(f"이미 있음: {ENV} 또는 {SECRETS_H} — 새로 만들려면 --force (장치 펌웨어도 다시 넣어야 함)")

    dev = {"device_id": "rtu-a1", "site_id": a.site, "token": secrets.token_urlsafe(24), "secret": secrets.token_hex(32)}
    other = {"device_id": "rtu-b1", "site_id": "site-b", "token": secrets.token_urlsafe(24), "secret": secrets.token_hex(32)}
    ops = [{"name": "operator-a", "token": secrets.token_urlsafe(24), "sites": [a.site]},
           {"name": "operator-b", "token": secrets.token_urlsafe(24), "sites": ["site-b"]}]
    ENV.write_text(
        "# 관제 서버 비밀값 — git 에 올리지 않는다\n"
        f"DEVICES={json.dumps([dev, other])}\n"
        f"OPERATORS={json.dumps(ops)}\n"
        "DB_PATH=/data/rtu.db\n"
        "# AI 보고서 (선택) — 없으면 규칙 기반 보고서\n"
        "ANTHROPIC_API_KEY=\n"
        "AI_MODEL=claude-haiku-5-5\n", encoding="utf-8")
    SECRETS_H.write_text(
        "// 장치 비밀값 — git 에 올리지 않는다 (.gitignore). provision.py 가 만듦\n"
        "#pragma once\n"
        '#define WIFI_SSID     "Wokwi-GUEST"\n'
        '#define WIFI_PASS     ""\n'
        '#define SERVER_URL    "https://CHANGE-ME.trycloudflare.com"   // 터널을 열 때마다 바뀐다\n'
        f'#define SITE_ID       "{dev["site_id"]}"\n'
        f'#define DEVICE_TOKEN  "{dev["token"]}"\n'
        f'#define DEVICE_SECRET "{dev["secret"]}"\n', encoding="utf-8")
    print(f"만듦: {ENV}\n만듦: {SECRETS_H}")
    print(f"운전원 토큰(site-a 조회 · 보고서용): {ops[0]['token']}")
    print("다음: server/.env 에 ANTHROPIC_API_KEY (선택) → docker compose up -d --build")


if __name__ == "__main__":
    main()
