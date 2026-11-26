# 태그가 아니라 다이제스트로 고정 (python:3.12-slim, 2026-11-26 기준)
FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b
WORKDIR /srv
COPY requirements.lock .
# requirements.txt → pip-compile --generate-hashes → requirements.lock. 해시가 하나라도 다르면 설치가 실패한다
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app ./app
COPY tests ./tests
RUN useradd -m rtu && mkdir -p /data && chown rtu /data
USER rtu
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
