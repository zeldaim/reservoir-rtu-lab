"""장치 요청 검증 — 토큰 · 서명(HMAC-SHA256) · 시각 · 일련번호.

장치는 요청마다 다음 헤더를 붙인다:
  Authorization: Bearer <장치 토큰>        → 어느 장치인지 (장치는 자기 사이트에만 보낼 수 있다)
  X-Timestamp:   <유닉스 초>               → 서버 시각과 ±MAX_SKEW_S 안이어야 (오래된 요청 재사용 차단)
  X-Seq:         <장치가 1씩 올리는 번호>   → 이미 받은 번호 이하면 거부 (같은 요청 다시 보내기 차단)
  X-Signature:   hex(HMAC_SHA256(장치 비밀, f"{ts}\\n{seq}\\n{본문}"))   → 본문 · 시각 · 번호가 안 바뀌었는지

토큰과 비밀은 따로다: 토큰은 "누구", 비밀은 "정말 그 장치인지 + 내용이 그대로인지". 서명 비교는 시간 차이로
값을 추측하지 못하게 hmac.compare_digest 로 한다.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

MAX_SKEW_S = 300


@dataclass(frozen=True)
class Device:
    device_id: str
    site_id: str
    token: str
    secret: bytes


class AuthError(Exception):
    """status · 이유 (응답에는 이유를 자세히 주지 않고 로그에만 남긴다)"""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def sign(secret: bytes, ts: int, seq: int, body: bytes) -> str:
    msg = f"{ts}\n{seq}\n".encode() + body
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify(devices_by_token: dict[str, Device], last_seq: dict[str, int], site_id: str,
           headers: dict[str, str], body: bytes, now: float | None = None) -> Device:
    """통과하면 장치를 돌려주고, 아니면 AuthError. last_seq 갱신은 부른 쪽이 저장에 성공한 뒤에 한다."""
    now = time.time() if now is None else now
    auth = headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise AuthError(401, "no_token")
    dev = devices_by_token.get(auth[7:].strip())
    if dev is None:
        raise AuthError(401, "unknown_token")
    if dev.site_id != site_id:
        raise AuthError(403, "wrong_site")             # 다른 사이트로 보내기 (장치 탈취 · 설정 실수)
    try:
        ts, seq = int(headers.get("x-timestamp", "")), int(headers.get("x-seq", ""))
    except ValueError:
        raise AuthError(400, "bad_ts_or_seq") from None
    if abs(now - ts) > MAX_SKEW_S:
        raise AuthError(401, "stale_timestamp")
    expected = sign(dev.secret, ts, seq, body)
    if not hmac.compare_digest(expected, headers.get("x-signature", "")):
        raise AuthError(401, "bad_signature")
    if seq <= last_seq.get(dev.device_id, 0):
        raise AuthError(409, "replayed_seq")
    return dev
