"""tools/ai_rule_propose.py 의 검증 하네스 시험 — AI 호출 없이, 손으로 만든 초안 3개로 확인한다.
  python tests/test_ai_rule_propose.py   (pydantic 필요)
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from ai_rule_propose import WindowDraft, validate, propose_loop  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def main():
    evading = json.load(open(os.path.join(FIXTURES, "ai_rule_evading.json"), encoding="utf-8"))
    normal = json.load(open(os.path.join(FIXTURES, "ai_rule_normal.json"), encoding="utf-8"))
    fails = 0

    good = WindowDraft(can_propose=True, name="slow-brute-6h", event_type="FAIL", window_minutes=360,
                       threshold=4, level="high")
    ok, msg = validate(good, evading, normal)
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  6시간/4회 초안 → 90분 간격 느린 시도를 잡아야 함 ({msg})")

    too_loose = WindowDraft(can_propose=True, name="too-loose", event_type="FAIL", window_minutes=1440,
                            threshold=3, level="high")
    ok, msg = validate(too_loose, evading, normal)
    fails += ok
    print(f"{'PASS' if not ok else 'FAIL'}  24시간/3회(너무 넓음) → 정상 운전 기록 오탐으로 버려져야 함 ({msg})")

    dup = WindowDraft(can_propose=True, name="dup-24h", event_type="FAIL", window_minutes=1440,
                      threshold=20, level="high")
    ok, msg = validate(dup, evading, normal)
    fails += ok
    print(f"{'PASS' if not ok else 'FAIL'}  기존 룰(24h/20) 그대로 → 애초에 못 잡아서 버려져야 함 ({msg})")

    def fake_proposer(evading_events, normal_events, client=None, model=None, prior_attempts=None):
        if not prior_attempts:
            return WindowDraft(can_propose=True, name="1차", event_type="FAIL", window_minutes=1440,
                              threshold=3, level="high")
        assert prior_attempts[0]["why_rejected"] is not None, "1차 실패 이유가 2차로 안 넘어감"
        return WindowDraft(can_propose=True, name="2차", event_type="FAIL", window_minutes=360,
                          threshold=4, level="high")

    draft, msg, attempts = propose_loop(evading, normal, max_attempts=3, proposer=fake_proposer)
    ok = draft is not None and draft.name == "2차" and len(attempts) == 2
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  재시도 루프 — 실패 이유를 받아 고치고 2번째에 통과 ({msg})")

    print(f"\n{'모두 통과' if not fails else f'실패 {fails}건'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
