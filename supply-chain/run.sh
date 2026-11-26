#!/usr/bin/env bash
# 공급망 점검 일괄: SBOM(syft, CycloneDX) → 취약점 스캔(grype) → 서명·검증(cosign, 로컬 키).
#   bash supply-chain/run.sh <이미지> [<이미지> …]      레포 루트에서
# 점검 도구도 다이제스트로 고정했다(아래). 도구가 바뀌면 결과 해석이 달라지므로 올릴 때는 이 값과 로그를 같이 바꾼다.
# 개인 키는 레포 밖($SUPPLY_KEYDIR, 기본 ~/.supply-chain-keys)에 둔다. 레포에는 공개 키(cosign.pub)와 서명 번들(*.bundle)만 둔다.
# 투명성 로그(Rekor)를 쓰지 않는다 — 망분리 환경이라 서명이 "이 키로 서명됐고 바뀌지 않았다"만 증명하고, 서명 시각은 증명하지 못한다.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=supply-chain
SYFT=anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a      # 1.57.2
GRYPE=anchore/grype@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c    # 0.122.1
COSIGN=ghcr.io/sigstore/cosign/cosign@sha256:7d08ec40d6f6fd9ced81a498c367ee6d4dd90d73218f58a791f78661bdbef769
KEYDIR=${SUPPLY_KEYDIR:-$HOME/.supply-chain-keys}
W=$(pwd -W 2>/dev/null || pwd)
export MSYS_NO_PATHCONV=1
mkdir -p "$OUT" "$KEYDIR"

cosign() { docker run --rm -e COSIGN_PASSWORD="" -v "$W/$OUT:/w" -v "$(cd "$KEYDIR" && pwd -W 2>/dev/null || echo "$KEYDIR"):/k" -w /w "$COSIGN" "$@"; }

if [ ! -f "$KEYDIR/cosign.key" ]; then
  echo "[키] 새 서명 키 쌍을 만든다 (개인 키는 $KEYDIR, 비밀번호 없음 — 실습용)"
  docker run --rm -e COSIGN_PASSWORD="" -v "$(cd "$KEYDIR" && pwd -W 2>/dev/null || echo "$KEYDIR"):/k" -w /k "$COSIGN" generate-key-pair >/dev/null
fi
cp "$KEYDIR/cosign.pub" "$OUT/cosign.pub"

SIGN=()
for img in "$@"; do
  name=$(echo "$img" | tr '/:' '--')
  echo "[SBOM] $img"
  docker run --rm -v //var/run/docker.sock:/var/run/docker.sock "$SYFT" "docker:$img" -o cyclonedx-json > "$OUT/sbom-$name.cdx.json"
  echo "[취약점] $img"
  docker run --rm -v "$W/$OUT:/w" "$GRYPE" "sbom:/w/sbom-$name.cdx.json" -o json > "$OUT/vulns-$name.json"
  python - "$OUT/sbom-$name.cdx.json" "$OUT/vulns-$name.json" "$img" <<'PY' | tee "$OUT/summary-$name.txt"
import json, sys, collections
sbom = json.load(open(sys.argv[1], encoding="utf-8")); v = json.load(open(sys.argv[2], encoding="utf-8"))
comps = [c for c in sbom.get("components", []) if c.get("type") in ("library", "application")]
m = v.get("matches", [])
sev = collections.Counter(x["vulnerability"]["severity"] for x in m)
fix = collections.Counter(("수정 버전 있음" if x["vulnerability"].get("fix", {}).get("state") == "fixed" else "수정 없음/미확정") for x in m)
print(f"이미지 {sys.argv[3]}")
print(f"SBOM 구성요소 {len(comps)}개 (CycloneDX)")
print(f"취약점 일치 {len(m)}건 — 심각도 {dict(sev)} · {dict(fix)}")
hi = [x for x in m if x["vulnerability"]["severity"] in ("Critical", "High")]
for x in sorted(hi, key=lambda x: x["vulnerability"]["id"])[:12]:
    a = x["artifact"]
    print(f"  {x['vulnerability']['severity']:8} {x['vulnerability']['id']:20} {a['name']} {a['version']} → 수정: {x['vulnerability'].get('fix', {}).get('versions') or '-'}")
PY
  SIGN+=("sbom-$name.cdx.json" "vulns-$name.json" "summary-$name.txt")
done

for f in requirements.lock requirements.in server/requirements.lock server/requirements.txt Dockerfile server/Dockerfile docker-compose.yml server/docker-compose.yml integrity/manifest.json; do
  [ -f "$f" ] && { cp "$f" "$OUT/signed-$(echo "$f" | tr '/' '-')"; SIGN+=("signed-$(echo "$f" | tr '/' '-')"); } || true
done

echo "[서명] ${#SIGN[@]}개 파일"
for f in "${SIGN[@]}"; do
  cosign sign-blob --key /k/cosign.key --use-signing-config=false --tlog-upload=false --yes --bundle "$f.bundle" "$f" >/dev/null 2>&1
done
echo "[검증]"
fail=0
for f in "${SIGN[@]}"; do
  if cosign verify-blob --key cosign.pub --bundle "$f.bundle" --insecure-ignore-tlog=true "$f" >/dev/null 2>&1; then echo "  OK   $f"; else echo "  FAIL $f"; fail=1; fi
done
exit $fail
