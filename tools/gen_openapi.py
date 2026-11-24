#!/usr/bin/env python3
"""서버 코드 → OpenAPI 명세 (문서 · API 목록용). 탐지는 이 파일을 보지 않는다 — app.main 의 라우트를 그 자리에서 직접 기준으로 쓴다
(명세 파일을 따로 두면 api-defense-lab 처럼 "손으로 고치면 명세와 어긋난다" 위험이 생기는데, 이 서버는 코드와 명세를 같은 사람이
만들어서 그 위험이 없다 — 그래서 탐지는 코드에서 바로, 이 파일은 사람이 읽는 문서용으로만 쓴다).

  python tools/gen_openapi.py [--out spec/rtu_openapi.json] [--vuln-bola]
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
os.environ.setdefault("RTU_AUTOSTART", "0")

from app.main import create_app  # noqa: E402
from app.store import Store  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="spec/rtu_openapi.json")
    ap.add_argument("--vuln-bola", action="store_true", help="LAB_VULN_BOLA=1 상태(취약 경로 /api/v0 포함)로 뽑기 — 기본은 뺀 상태")
    a = ap.parse_args()
    app = create_app(store=Store(":memory:"), devices={}, operators={}, vuln_bola=a.vuln_bola)
    spec = app.openapi()
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ops = sorted(f"{m.upper()} {p}" for p, item in spec["paths"].items() for m in item if m != "parameters")
    print(f"→ {a.out} ({len(ops)}개 작업)")
    for o in ops:
        print(f"  {o}")


if __name__ == "__main__":
    main()
