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
# 중간 인증서(server/tools/ca/*.pem)를 루트보다 앞에 신뢰 목록으로 넣는다. 장치(mbedTLS)는 신뢰 목록에 있는 중간 인증서에서
# 확인을 멈추므로, 무거운 P-384 서명 검증(WE1 ← GTS Root R4)을 건너뛴다. Wokwi 에서 끝까지 확인하면 핸드셰이크가 17초를 넘겨
# Cloudflare 가 끊었음(-29312). 중간 인증서가 바뀌면 루트로 확인(느리지만 정확).
# 추가 전 확인: openssl verify -partial_chain -CAfile <루트>.pem server/tools/ca/WE1.pem → OK (2026-11-23, 만료 2029-02-20)
CA_DIR = Path(__file__).resolve().parent / "ca"
OUT = Path(__file__).resolve().parents[2] / "firmware" / "rtu" / "ca_roots.h"


def main():
    pem = Path(certifi.where()).read_text(encoding="utf-8")
    found = dict(re.findall(r'# Label: "([^"]+)"\n(?:#[^\n]*\n)*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', pem, re.S))
    missing = [w for w in WANT if w not in found]
    if missing:
        raise SystemExit(f"certifi 에 없음: {missing}")
    lines = ["// 서버(터널 주소) 인증서를 확인할 신뢰 목록 (중간 인증서 + 루트 CA) — 공개 인증서라 git 에 올려도 된다.",
             "// 만든 것: server/tools/make_ca_roots.py (certifi 번들에서). 직접 고치지 말 것.",
             "#pragma once", "static const char CA_ROOTS[] ="]
    for f in sorted(CA_DIR.glob("*.pem")):
        lines.append(f"  // 중간 인증서 {f.stem} (빠른 확인용)")
        lines += [f'  "{l}\\n"' for l in f.read_text(encoding="utf-8").strip().splitlines()]
    for w in WANT:
        lines.append(f"  // {w}")
        lines += [f'  "{l}\\n"' for l in found[w].splitlines()]
    lines.append("  ;")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"만듦: {OUT} (중간: {', '.join(f.stem for f in sorted(CA_DIR.glob('*.pem'))) or '없음'} · 루트: {', '.join(WANT)})")


if __name__ == "__main__":
    main()
