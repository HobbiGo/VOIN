#!/usr/bin/env bash
# Local source checks only. Never starts/stops nodes, signs transactions,
# uploads files, commits changes, or reads validator/private-key files.
set -uo pipefail
umask 077
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo 'Jalankan dari dalam repository VOIN.'; exit 2;
}
APP="$ROOT/consensus/voin-app"
[ -f "$APP/go.mod" ] || { echo 'Modul Go VOIN tidak ditemukan.'; exit 2; }
command -v timeout >/dev/null || { echo 'Perintah timeout diperlukan.'; exit 2; }
OUT=$(mktemp -d "${TMPDIR:-/tmp}/voin-check.XXXXXX") || exit 2
SUMMARY="$OUT/summary.txt"
FAILED=0
printf 'VOIN SOURCE CHECK\nBranch: %s\nCommit: %s\n\n' \
  "$(git -C "$ROOT" branch --show-current)" \
  "$(git -C "$ROOT" rev-parse --short HEAD)" > "$SUMMARY"
run_check() {
  local name="$1"; shift
  local code
  printf 'RUN: %s\n' "$name"
  timeout --signal=TERM --kill-after=10s 240s "$@" > "$OUT/$name.log" 2>&1
  code=$?
  if [ "$code" -eq 0 ]; then
    printf 'PASS: %s\n' "$name" | tee -a "$SUMMARY"
  else
    FAILED=$((FAILED+1))
    printf 'FAIL: %s (exit %s)\n' "$name" "$code" | tee -a "$SUMMARY"
    if [ "$code" -eq 124 ] || [ "$code" -eq 137 ]; then
      printf '  Batas waktu tercapai; bukan bukti kegagalan logika.\n' | tee -a "$SUMMARY"
    fi
    tail -n 12 "$OUT/$name.log" | tee -a "$SUMMARY"
  fi
}
run_check go-format bash -c '
  cd "$1" || exit 1
  files=$(find . -type f -name "*.go" -not -path "./vendor/*") || exit 1
  [ -n "$files" ] || exit 1
  result=$(printf "%s\n" "$files" | xargs gofmt -l) || exit 1
  [ -z "$result" ] || { printf "%s\n" "$result"; exit 1; }
' _ "$APP"
run_check go-tests bash -c 'cd "$1" && go test ./... -count=1 -timeout=120s' _ "$APP"
run_check go-race bash -c 'cd "$1" && go test -race ./... -count=1 -timeout=120s' _ "$APP"
run_check go-vet bash -c 'cd "$1" && go vet ./...' _ "$APP"
run_check python-tests bash -c '
  cd "$1" || exit 1
  python -m unittest discover -s tests
' _ "$ROOT"
printf '\n' | tee -a "$SUMMARY"
if [ "$FAILED" -eq 0 ]; then
  printf 'SOURCE CHECK PASS. Belum membuktikan transfer melalui jaringan.\n' | tee -a "$SUMMARY"
else
  printf '%s pemeriksaan belum lulus. Jangan deploy dulu.\n' "$FAILED" | tee -a "$SUMMARY"
fi
printf 'Log lokal: %s\n' "$OUT" | tee -a "$SUMMARY"
printf 'Tidak ada node, saldo, genesis, atau Git commit yang diubah.\n' | tee -a "$SUMMARY"
[ "$FAILED" -eq 0 ]
