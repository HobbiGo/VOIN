#!/usr/bin/env bash
# VOIN development checks. No wallet CLI, transfers, deletion, commit, or push.
set -u
set -o pipefail
export GIT_PAGER=cat
export GIT_TERMINAL_PROMPT=0
pass=0
fail=0
run_check() {
  local label="$1"
  shift
  printf '\nCHECK: %s\n' "$label"
  if "$@"; then
    printf 'PASS: %s\n' "$label"
    pass=$((pass+1))
  else
    printf 'FAIL: %s\n' "$label"
    fail=$((fail+1))
  fi
}
repo=$(git rev-parse --show-toplevel 2>/dev/null) || { echo 'STOP: jalankan dari repositori VOIN'; exit 2; }
cd "$repo" || exit 2
if [[ ! -f consensus/voin-app/go.mod || ! -d tests ]]; then
  echo 'STOP: struktur repositori VOIN tidak sesuai'
  exit 2
fi
printf 'VOIN CHECK - tanpa transaksi\n'
printf 'Tes menjalankan kode repositori: gunakan hanya pada repositori yang Anda percaya.\n'
printf 'Go dapat mengunduh dependency dan menulis cache; tes dapat membuat file sementara.\n'
printf 'Skrip ini tidak memanggil wallet, membaca file kunci, atau meminta passphrase.\n'
run_check 'Git branch' git branch --show-current
run_check 'Git status (nama file saja)' git status --short
run_check 'Whitespace perubahan lokal' git diff --check
run_check 'Whitespace perubahan siap commit' git diff --cached --check
check_ignore() {
  local path
  local result=0
  for path in voin-test-wallets/contoh.json voin-encrypted-test-wallets/contoh.enc voin-encrypted-test-backups/contoh.backup.enc contoh-wallet.json contoh.enc contoh.enc.txt contoh.key contoh.pem .env .env.local; do
    if git check-ignore --no-index -q -- "$path"; then
      printf 'IGNORED: %s\n' "$path"
    else
      printf 'NOT IGNORED: %s\n' "$path"
      result=1
    fi
  done
  return "$result"
}
run_check 'Aturan pengecualian file contoh' check_ignore
check_tracked() {
  local found
  found=$(git ls-files -- '*wallet*.json' '*.enc' '*.enc.txt' '*.key' '*.pem' '*backup*' '.env' '.env.*') || return 1
  # .env.example is intentionally allowed; other matches require manual review.
  found=$(printf '%s\n' "$found" | grep -vE '(^|/)\.env\.example$' || true)
  if [[ -n "$found" ]]; then
    printf 'REVIEW nama file yang cocok (belum tentu rahasia):\n%s\n' "$found"
    return 1
  fi
  echo 'Tidak ada nama file terlacak yang cocok dengan pola pemeriksaan.'
  echo 'Bukan pemindaian isi atau riwayat Git.'
}
run_check 'Pola nama sensitif dalam file terlacak' check_tracked
if command -v go >/dev/null 2>&1; then
  run_check 'Go race tests' bash -c 'cd consensus/voin-app && go test -race ./... -count=1 -timeout=180s'
  run_check 'Go vet' bash -c 'cd consensus/voin-app && go vet ./...'
else
  echo 'FAIL: Go tidak ditemukan'
  fail=$((fail+1))
fi
if command -v python3 >/dev/null 2>&1; then
  run_check 'Python tests' python3 -m unittest discover -s tests
elif command -v python >/dev/null 2>&1; then
  run_check 'Python tests' python -m unittest discover -s tests
else
  echo 'FAIL: Python tidak ditemukan'
  fail=$((fail+1))
fi
printf '\nSUMMARY: %s PASS, %s FAIL\n' "$pass" "$fail"
echo 'PASS bukan audit keamanan atau bukti siap produksi.'
echo 'Checksum backup perangkat belum diverifikasi oleh skrip ini.'
echo 'Tidak ada transfer, penghapusan kunci, commit, atau push yang diminta oleh skrip ini.'
if [[ "$fail" -ne 0 ]]; then exit 1; fi
