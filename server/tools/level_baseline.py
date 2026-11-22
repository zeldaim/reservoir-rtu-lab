#!/usr/bin/env python3
"""4단계 b (예비) — 실제 K-water 정수지 · 배수지 수위로 "정상 변화 속도" 기준선 만들기.

데이터: aquaflow-pipeline 이 모은 공공데이터(curated_level ORC, 탱크별 시간 단위 수위 m).
방법: 탱크마다 시간순으로 이웃한 두 점의 |수위 차| ÷ 시간(시) = 시간당 변화량(m/h) → 전체 · 종류별 분위수.
       데이터가 적을 때는 ML 대신 이런 통계 기준선이 정직하다 (1주 이상 쌓이면 다시 돌리고 ML 과 비교).

  docker run --rm -v D:/aquaflow-pipeline:/lake -v D:/reservoir-rtu-lab:/repo --entrypoint python \\
      aquaflow-pipeline-aquaflow:latest /repo/server/tools/level_baseline.py --lake /lake/data/lake --out /repo/docs/data

출력: level_baseline.json (기준선) · level_baseline.md (표)
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.orc as orc


def quantile(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    i = (len(xs) - 1) * q
    lo, hi = int(i), min(int(i) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lake", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    files = sorted(Path(a.lake, "curated_level").glob("date=*/part-0.orc"))
    t = pa.concat_tables([orc.read_table(str(f)) for f in files]).to_pylist()

    series = defaultdict(dict)                       # (시설, 탱크) → {시각: 수위} (같은 시각 중복은 마지막 값)
    kind = {}
    for r in t:
        if r["level_m"] is None or r["ts"] is None:
            continue
        k = (r["facility_code"], r["tag"])
        series[k][r["ts"]] = float(r["level_m"])
        kind[k] = r["kind"]

    rates = defaultdict(list)                        # 종류 → 시간당 변화량 |m/h|
    for k, pts in series.items():
        ts = sorted(pts)
        for t0, t1 in zip(ts, ts[1:]):
            h = (t1 - t0).total_seconds() / 3600
            if 0 < h <= 3:                           # 빈 구간이 3시간 넘으면 변화량으로 안 씀
                rates[kind[k]].append(abs(pts[t1] - pts[t0]) / h)
    rates["전체"] = [x for v in list(rates.values()) for x in v]

    span = (min(r["ts"] for r in t), max(r["ts"] for r in t))
    out = {"source": "K-water 공공데이터 정수지·배수지 수위 (aquaflow-pipeline curated_level)",
           "period": [str(span[0]), str(span[1])], "rows": len(t), "tanks": len(series),
           "preliminary": True, "note": "데이터 1주 미만 — 예비 기준선. 1주 이상 쌓이면 다시 계산",
           "rate_m_per_h": {}}
    for kd, xs in sorted(rates.items(), key=lambda kv: kv[0] != "전체"):
        out["rate_m_per_h"][kd] = {"n": len(xs), "median": quantile(xs, .5), "p95": quantile(xs, .95),
                                   "p99": quantile(xs, .99), "max": max(xs) if xs else None}
    Path(a.out).mkdir(parents=True, exist_ok=True)
    Path(a.out, "level_baseline.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    lines = [f"# 수위 정상 변화 속도 기준선 (예비)", "",
             f"- 데이터: {out['source']}", f"- 기간: {out['period'][0]} ~ {out['period'][1]} · {out['rows']:,}행 · 탱크 {out['tanks']}개",
             f"- {out['note']}", "", "| 종류 | 변화 수 | 중앙값 (cm/h) | p95 | p99 | 최대 |", "|---|---|---|---|---|---|"]
    for kd, s in out["rate_m_per_h"].items():
        f = (lambda v: f"{v * 100:.1f}" if v is not None else "-")
        lines.append(f"| {kd} | {s['n']:,} | {f(s['median'])} | {f(s['p95'])} | {f(s['p99'])} | {f(s['max'])} |")
    Path(a.out, "level_baseline.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
