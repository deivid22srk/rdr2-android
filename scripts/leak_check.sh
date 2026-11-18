#!/bin/sh
# Fails if any material derived from the game reached this public repository.
#
# Checked: PE images (MZ), game containers (.rpf), executables/libraries,
# anything over 5 MB, and the generated-code folder.
#
# This repo is public. Its artifacts are visible to anyone logged in, so the
# only safe rule is: nothing game-derived is ever committed here.
set -eu

fail=0

report() { printf '  %s\n' "$1"; fail=1; }

echo "== executáveis e imagens PE =="
for f in $(git ls-files); do
  case "$f" in
    *.exe|*.dll|*.sys|*.com|*.pdb|*.lib|*.obj|*.so.*) report "$f (extensão)"; continue ;;
  esac
  # PE magic in any tracked file, whatever its name.
  if [ -f "$f" ] && [ "$(head -c 2 "$f" 2>/dev/null)" = "MZ" ]; then
    report "$f (assinatura MZ)"
  fi
done

echo "== dados do jogo =="
for f in $(git ls-files); do
  case "$f" in
    *.rpf|*.rpf.*|*.ytd|*.ymt|*.yft|*.rel|*.awc|*.bik|*.bk2) report "$f (container do jogo)" ;;
  esac
done

echo "== diretórios derivados do jogo =="
for d in gen crack codegen game "Red Dead Redemption 2" work; do
  if [ -d "$d" ] && [ "$(git ls-files "$d" | wc -l)" -gt 0 ]; then
    report "$d/ versionado"
  fi
done

echo "== tamanho dos arquivos versionados =="
big=$(git ls-files -z | xargs -0 -r du -k 2>/dev/null | awk '$1 > 5120 {print $1 " KB  " $2}')
if [ -n "$big" ]; then
  printf '%s\n' "$big" | while read -r line; do report "$line"; done
fi

echo "== hashes de material do jogo =="
if git grep -qE '\b[0-9a-f]{64}\b' -- . ':!docs' 2>/dev/null; then
  # A 64-hex digest outside docs/ is either a manifest (must live in the private
  # repo) or an accidental copy of one.
  report "hash SHA-256 encontrado fora de docs/"
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "FALHOU: material do jogo ou derivado dele no repositório público." >&2
  echo "O codegen e o manifesto de hashes pertencem ao repositório privado." >&2
  exit 1
fi
echo
echo "OK: nada do jogo no repositório."
