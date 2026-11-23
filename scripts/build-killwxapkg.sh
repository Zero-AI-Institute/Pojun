#!/usr/bin/env bash
# build-killwxapkg.sh — 构建 KillWxapkg Linux 二进制（MIT）。
#
# 官方 Release 只有 darwin/windows；本脚本按需交叉编译 linux/amd64+arm64，
# 用于本地验证或 release 资产补建。
#
# 用法：bash scripts/build-killwxapkg.sh [--out dist]
set -euo pipefail

VER="${KILLWXAPKG_VERSION:-v2.4.1}"
OUT="dist"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-dist}"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone --depth 1 --branch "$VER" https://github.com/Ackites/KillWxapkg "$TMP/src"
cd "$TMP/src"

for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w" -o "$OUT/killwxapkg_linux_$arch" .
  echo "built $OUT/killwxapkg_linux_$arch"
done

cp LICENSE "$OUT/KillWxapkg-LICENSE"
cd "$OUT"
sha256sum killwxapkg_linux_* KillWxapkg-LICENSE > KillWxapkg-SHA256SUMS
echo "OK: $OUT"
