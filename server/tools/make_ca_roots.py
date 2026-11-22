#!/usr/bin/env python3
"""firmware/rtu/ca_roots.h 만들기 — 장치가 서버(터널) 인증서를 확인할 루트 CA (공개 인증서).

  python server/tools/make_ca_roots.py

출처는 certifi 번들 (pip install certifi). 터널 주소의 발급자가 바뀌면 WANT 에 루트를 더한다.
2026-11-23 확인: *.trycloudflare.com = Google Trust Services WE1 → GTS Root R4.
"""
import re
from pathlib import Path

import certifi

WANT = ["GTS Root R1", "GTS Root R4", "ISRG Root X1", "ISRG Root X2"]
OUT = Path(__file__).resolve().parents[2] / "firmware" / "rtu" / "ca_roots.h"


def main():
    pem = Path(certifi.where()).read_text(encoding="utf-8")
    found = dict(re.findall(r'# Label: "([^"]+)"\n(?:#[^\n]*\n)*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', pem, re.S))
    missing = [w for w in WANT if w not in found]
    if missing:
        raise SystemExit(f"certifi 에 없음: {missing}")
    lines = ["// 서버(터널 주소) 인증서를 확인할 루트 CA — 공개 인증서라 git 에 올려도 된다.",
             "// 만든 것: server/tools/make_ca_roots.py (certifi 번들에서). 직접 고치지 말 것.",
             "#pragma once", "static const char CA_ROOTS[] ="]
    for w in WANT:
        lines.append(f"  // {w}")
        lines += [f'  "{l}\\n"' for l in found[w].splitlines()]
    lines.append("  ;")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"만듦: {OUT} ({', '.join(WANT)})")


if __name__ == "__main__":
    main()
