"""관제 서버 — 장치 사건 받기 · 조회 · AI 사고 리포트.

  POST /api/v1/sites/{site}/events    장치 → 서버 (토큰 + HMAC 서명 + 시각 + 일련번호)
  GET  /api/v1/sites/{site}/summary   장치 ← 서버 (LCD 한 줄, 장치 토큰)
  GET  /api/v1/sites/{site}/events    운전원 조회 (운전원 토큰 — 자기 사이트만)
  POST /api/v1/sites/{site}/report    운전원이 보고서 만들기 (최근 N분 사건 → AI)
  GET  /healthz

설정 (.env — git 에 안 올림):
  DEVICES   장치 목록 JSON: [{"device_id","site_id","token","secret"}]
  OPERATORS 운전원 목록 JSON: [{"name","token","sites":[...]}]
  ANTHROPIC_API_KEY (선택) · AI_MODEL (선택, 기본 claude-haiku-5-5) · DB_PATH
"""
from __future__ import annotations

import json
import logging
import os
import re
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import detect
from . import report as reportmod
from .security import AuthError, Device, verify
from .store import Store

log = logging.getLogger("rtu")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MAX_BODY = 8 * 1024          # 장치 한 번 전송 최대 (사건 수십 건) — 큰 본문으로 서버 괴롭히기 차단
MAX_EVENTS = 50


def load_devices() -> dict[str, Device]:
    out = {}
    for d in json.loads(os.environ.get("DEVICES", "[]")):
        out[d["token"]] = Device(d["device_id"], d["site_id"], d["token"], d["secret"].encode())
    return out


def load_operators() -> dict[str, dict]:
    return {o["token"]: o for o in json.loads(os.environ.get("OPERATORS", "[]"))}


def create_app(store: Store | None = None, devices: dict | None = None, operators: dict | None = None,
               ai_client=None, vuln_bola: bool | None = None) -> FastAPI:
    app = FastAPI(title="reservoir-rtu control server", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store or Store(os.environ.get("DB_PATH", "/data/rtu.db"))
    app.state.devices = devices if devices is not None else load_devices()
    app.state.operators = operators if operators is not None else load_operators()
    app.state.last_seq = app.state.store.last_seq()
    app.state.ai_client = ai_client
    # 5단계 시연용 취약 경로 — 기본 꺼짐. 터널(인터넷)을 연 채로 켜지 말 것
    app.state.vuln_bola = vuln_bola if vuln_bola is not None else os.environ.get("LAB_VULN_BOLA") == "1"

    def record_cross_site(op: dict, site_id: str, allowed: bool, path: str) -> None:
        """다른 사이트 접근을 '당한 사이트' 쪽 탐지 기록에 남김 — 그 사이트 운전원이 누가 엿봤는지 볼 수 있게.
        allowed=True 는 취약 경로에서 실제로 새어 나간 것(BOLA 성공), False 는 권한 검사가 막은 시도."""
        det = {"kind": "BOLA_LEAK" if allowed else "CROSS_SITE_DENIED", "window": "즉시",
               "operator": op.get("name"), "path": path,
               "detail": f"다른 사이트 운전원 {op.get('name')} 가 {path} 접근 — " + ("응답이 나감(권한 검사 없음)" if allowed else "403 으로 막음")}
        app.state.store.add_detection(site_id, det, dedupe_s=0)
        log.warning("cross-site op=%s site=%s allowed=%s path=%s", op.get("name"), site_id, allowed, path)

    def operator_for(request: Request, site_id: str) -> dict:
        auth = request.headers.get("authorization", "")
        op = app.state.operators.get(auth[7:].strip()) if auth.startswith("Bearer ") else None
        if op is None:
            raise HTTPException(401, "unauthorized")
        if site_id not in op.get("sites", []):            # 객체 단위 권한 — 다른 사이트 조회 막기 (5단계 BOLA 시연의 '고친 쪽')
            record_cross_site(op, site_id, allowed=False, path=request.url.path)
            raise HTTPException(403, "forbidden")
        return op

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/api/v1/sites/{site_id}/events")
    async def post_events(site_id: str, request: Request):
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "too large")
        headers = {k.lower(): v for k, v in request.headers.items()}
        try:
            dev = verify(app.state.devices, app.state.last_seq, site_id, headers, body)
        except AuthError as e:
            log.warning("reject device request site=%s reason=%s ip=%s", site_id, e.reason, headers.get("x-client-ip", "-"))
            return JSONResponse({"error": "rejected"}, status_code=e.status)   # 이유는 로그에만
        try:
            data = json.loads(body)
            events = data["events"]
            assert isinstance(events, list) and 0 < len(events) <= MAX_EVENTS
            assert all(isinstance(e, dict) and "type" in e for e in events)
        except Exception:
            raise HTTPException(400, "bad body")
        seq = int(headers["x-seq"])
        n = app.state.store.add_events(site_id, dev.device_id, seq, events)
        app.state.last_seq[dev.device_id] = seq          # 저장에 성공한 뒤에만 올린다
        now = time.time()                                # 4단계 a: 긴 창으로 느린 무차별 대입 탐지
        for det in detect.slow_bruteforce(app.state.store.events(site_id, now - 24 * 3600, limit=5000), now):
            if app.state.store.add_detection(site_id, det, detect.DEDUPE_S):
                log.warning("detection site=%s %s", site_id, det["detail"])
        return {"stored": n, "seq": seq}

    @app.get("/api/v1/sites/{site_id}/summary")
    def get_summary(site_id: str, request: Request):
        auth = request.headers.get("authorization", "")
        dev = app.state.devices.get(auth[7:].strip()) if auth.startswith("Bearer ") else None
        if dev is None or dev.site_id != site_id:
            raise HTTPException(401, "unauthorized")
        r = app.state.store.latest_report(site_id)
        return {"lcd_line": r["lcd_line"] if r else "NO REPORT YET", "risk_level": r["risk_level"] if r else None}

    @app.get("/api/v1/sites/{site_id}/events")
    def get_events(site_id: str, request: Request, minutes: int = 60):
        operator_for(request, site_id)
        return {"events": app.state.store.events(site_id, time.time() - max(1, min(minutes, 1440)) * 60)}

    if app.state.vuln_bola:
        # ── 취약한 경로 (시연용) ── 토큰이 '어떤 운전원'인지만 보고, 그 운전원이 이 사이트 담당인지는 안 본다.
        # 주소의 site_id 만 바꾸면 남의 사이트 사건이 보인다 = BOLA (OWASP API Security Top 10 API1:2023).
        @app.get("/api/v0/sites/{site_id}/events")
        def get_events_vuln(site_id: str, request: Request, minutes: int = 60):
            auth = request.headers.get("authorization", "")
            op = app.state.operators.get(auth[7:].strip()) if auth.startswith("Bearer ") else None
            if op is None:
                raise HTTPException(401, "unauthorized")
            if site_id not in op.get("sites", []):        # 막지는 않고(취약) 기록만 — 탐지는 되는데 피해는 이미 난 상태
                record_cross_site(op, site_id, allowed=True, path=request.url.path)
            return {"events": app.state.store.events(site_id, time.time() - max(1, min(minutes, 1440)) * 60)}

    @app.get("/api/v1/sites/{site_id}/detections")
    def get_detections(site_id: str, request: Request, minutes: int = 1440):
        operator_for(request, site_id)
        return {"detections": app.state.store.detections(site_id, time.time() - max(1, min(minutes, 10080)) * 60)}

    @app.post("/api/v1/sites/{site_id}/report")
    def post_report(site_id: str, request: Request, minutes: int = 60):
        operator_for(request, site_id)
        since = time.time() - max(1, min(minutes, 1440)) * 60
        events = app.state.store.events(site_id, since)
        # 서버 탐지도 사건처럼 넘긴다 — 규칙 · AI 보고서가 함께 판단 (장치 사건과 구분되게 SRV_ 접두어)
        events += [{"device_t": int(d["created_at"]), "type": "SRV_BRUTE", "detail": d["detail"]}
                   for d in app.state.store.detections(site_id, since)]
        engine, rep = reportmod.make_report(events, client=app.state.ai_client)
        app.state.store.save_report(site_id, engine, rep)
        return {"engine": engine, "events": len(events), "report": rep}

    # 6단계 — 숨은 API 탐지: 명세(= 이 라우트 목록 자체, spec/rtu_openapi.json 은 사람이 읽는 문서용)에
    # 없는 (메서드, 경로) 호출은 FastAPI 가 404 · 405 로 답한다. 그걸 그 자리에서 사건처럼 기록한다.
    # 명세 파일을 따로 두지 않아 "손으로 고치면 명세와 어긋난다"는 위험 자체가 없다 (tools/gen_openapi.py 참고).
    SITE_RE = re.compile(r"^/api/v\d+/sites/([^/]+)/")

    @app.exception_handler(StarletteHTTPException)
    async def shadow_api_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code in (404, 405) and request.url.path.startswith("/api/"):
            m = SITE_RE.match(request.url.path)
            site_id = m.group(1) if m else "_system"
            # window 를 "메서드 경로"로 써서 중복 제거(site_id·kind·window 조합, store.add_detection)가
            # 경로가 다른 또 다른 탐색까지 묻어 버리지 않게 한다 (같은 경로 재요청만 60초 동안 한 번).
            det = {"kind": "SHADOW_API_PROBE", "window": f"{request.method} {request.url.path}",
                  "method": request.method, "path": request.url.path,
                  "detail": f"명세에 없는 호출: {request.method} {request.url.path} ({exc.status_code})"}
            if app.state.store.add_detection(site_id, det, dedupe_s=60):
                log.warning("shadow-api site=%s %s %s -> %s", site_id, request.method, request.url.path, exc.status_code)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app


app = create_app() if os.environ.get("RTU_AUTOSTART", "1") == "1" else None
