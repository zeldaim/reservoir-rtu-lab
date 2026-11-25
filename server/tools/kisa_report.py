#!/usr/bin/env python3
"""KISA 점검 보고서 생성 (9단계) — 체크리스트 + 증거만 보고 AI가 항목별 판정·근거·조치를 쓴다.

증거가 있는 항목만 판정한다 (docs/data/kisa_evidence.json). 증거 없는 항목을 AI가 추측하게 하지 않는다 —
`app/report.py`의 사고 리포트와 같은 원칙: 출력은 정해진 스키마로만, 근거 없는 추측은 하지 않는다.

  python kisa_report.py --checklist docs/data/kisa_checklist.json --evidence docs/data/kisa_evidence.json \\
      --out docs/data/kisa_report_<날짜>.md
  (ANTHROPIC_API_KEY 없으면 --no-ai 로 증거 유무만 나열하는 최소 보고서)

docker 예시 (레포 루트에서):
  docker run --rm -e ANTHROPIC_API_KEY -v "%cd%:/repo" -w /repo --entrypoint python python:3.12-slim \\
      -c "pip install -q anthropic pydantic && python server/tools/kisa_report.py"
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import date
from typing import List, Literal

from pydantic import BaseModel, Field

SYSTEM_PROMPT = """너는 주요정보통신기반시설 기술적 취약점 분석·평가(KISA 2026년판) 점검관이다.
무인 배수지 원격감시 RTU(장치) + 관제 서버로 이루어진 학생 프로젝트를 점검한다.

각 항목에 대해 <evidence> 안의 사실 하나만 보고 판정한다. 그 사실에 없는 내용은 모른다고 하고,
근거 없이 "양호"라고 단정하지 않는다. evidence 의 category 가 이미 참고용으로 붙어 있지만
(강하게_맞음·미흡·해당없음_상충·평가불가·적용_가능), 너는 그 category 를 그대로 베끼지 말고
fact 내용을 직접 읽고 스스로 판정해라 — category 는 사람이 분류한 힌트일 뿐이다.

판정 기준:
  양호: 근거가 그 항목의 요구사항을 충족한다고 분명히 보여준다
  취약: 근거가 요구사항 미충족을 보여준다
  평가불가: 실물 장치가 없는 등 구조적으로 확인할 방법이 없다 (해당없음과 다르다 — "모른다"는 뜻)
  해당없음: 이 프로젝트 구조상 그 위협 자체가 없거나 항목 취지와 다른 방향이다
  부분충족: 요구사항 일부만 충족한다

근거(evidence)에 없는 내용을 지어내지 마라. 조치는 학생 프로젝트 범위에서 실제로 할 수 있는 것만 적어라
(예산·인력이 드는 전사 정책 수립 같은 건 "범위 밖"이라고 적어라)."""


class ItemVerdict(BaseModel):
    code: str
    verdict: Literal["양호", "취약", "평가불가", "해당없음", "부분충족"]
    reason: str = Field(description="판정 근거 — 준 evidence 를 바탕으로, 1~3문장")
    action: str = Field(description="조치. 이미 양호하거나 해당없음·평가불가면 '해당 없음'이라고 써도 됨")


class KisaReport(BaseModel):
    items: List[ItemVerdict]
    overall_note: str = Field(description="전체 점검에 대한 1~2문장 요약 — 범위의 한계(증거 있는 항목만 봤다는 점 등)를 포함")


def load(path: str) -> dict:
    return json.load(open(path, encoding="utf-8"))


def title_map(checklist: dict) -> dict:
    out = {}
    for section in (checklist["unix"], checklist["control_system"]):
        for items in section["categories"].values():
            for it in items:
                out[it["code"]] = it["title"]
    return out


def claude_judge(evidence_items: list[dict], titles: dict, client=None, model: str | None = None) -> dict:
    import anthropic

    client = client or anthropic.Anthropic()
    payload = [{"code": e["code"], "title": titles.get(e["code"], "?"), "category_hint": e["category"],
               "fact": e["fact"]} for e in evidence_items]
    response = client.messages.parse(
        model=model or os.environ.get("AI_MODEL", "claude-haiku-5-5"),
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"<evidence>\n{json.dumps(payload, ensure_ascii=False)}\n</evidence>"}],
        output_format=KisaReport,
    )
    if response.stop_reason == "refusal":
        raise RuntimeError(f"AI 거절: {getattr(response.stop_details, 'category', None)}")
    if response.parsed_output is None:
        raise RuntimeError(f"AI 출력 없음 (stop_reason={response.stop_reason})")
    return response.parsed_output.model_dump()


def no_ai_report(evidence_items: list[dict], titles: dict) -> dict:
    """AI 없이 — 증거 유무만 나열, 판정은 안 함 (AI 키 없을 때 대체)."""
    return {"items": [{"code": e["code"], "verdict": "부분충족", "reason": f"[AI 미사용] 증거: {e['fact']}",
                       "action": "ANTHROPIC_API_KEY 로 다시 돌려 실제 판정 필요"} for e in evidence_items],
           "overall_note": "AI 없이 돌림 — 증거만 나열했고 실제 판정은 안 됨. --no-ai 없이 다시 돌릴 것"}


def render_md(report: dict, titles: dict, evidence_by_code: dict) -> str:
    lines = [f"# KISA 점검 보고서 (증거 있는 항목만, {date.today().isoformat()})", "",
             "> AI가 `docs/data/kisa_evidence.json`의 사실만 보고 판정했다. 여기 없는 항목은 아직 점검 안 됨 —",
             "> `docs/data/kisa_applicability.md`의 '적용 가능' 표를 참고해 증거를 더 채운 뒤 다시 돌릴 것.", "",
             f"**전체 메모:** {report['overall_note']}", "",
             "| 코드 | 항목 | 판정 | 근거 | 조치 |", "|---|---|---|---|---|"]
    for it in report["items"]:
        lines.append(f"| {it['code']} | {titles.get(it['code'], '?')} | **{it['verdict']}** | {it['reason']} | {it['action']} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checklist", default="docs/data/kisa_checklist.json")
    ap.add_argument("--evidence", default="docs/data/kisa_evidence.json")
    ap.add_argument("--out", default=f"docs/data/kisa_report_{date.today().isoformat()}.md")
    ap.add_argument("--no-ai", action="store_true")
    a = ap.parse_args()

    checklist = load(a.checklist)
    evidence = load(a.evidence)
    titles = title_map(checklist)
    evidence_by_code = {e["code"]: e for e in evidence["items"]}

    if a.no_ai or not os.environ.get("ANTHROPIC_API_KEY"):
        report = no_ai_report(evidence["items"], titles)
        engine = "없음(증거만 나열)"
    else:
        report = claude_judge(evidence["items"], titles)
        engine = "claude"

    md = render_md(report, titles, evidence_by_code)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    open(a.out, "w", encoding="utf-8").write(md)
    print(f"엔진: {engine} · 항목 {len(report['items'])}개 → {a.out}")


if __name__ == "__main__":
    main()
