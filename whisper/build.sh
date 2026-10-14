#!/usr/bin/env bash
set -euo pipefail

export GOWORK=off

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_NAME="whisper"
ZIP_OUT="$PLUGIN_DIR/$PLUGIN_NAME.zip"

if [ -z "${BUILD_TARGETS:-}" ]; then
  BUILD_TARGETS="$(go env GOOS)-$(go env GOARCH)"
fi

cd "$PLUGIN_DIR"

for target in $BUILD_TARGETS; do
  TARGET_OS="${target%%-*}"
  TARGET_ARCH="${target#*-}"
  case "$TARGET_OS" in
    windows) EXT="dll" ;;
    darwin)  EXT="dylib" ;;
    *)       EXT="so" ;;
  esac

  OUTFILE="$PLUGIN_DIR/$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.$EXT"

  echo "[build] GOOS=$TARGET_OS GOARCH=$TARGET_ARCH > $OUTFILE"
  export GOOS="$TARGET_OS"
  export GOARCH="$TARGET_ARCH"
  export CGO_ENABLED=1
  case "$TARGET_OS-$TARGET_ARCH" in
    windows-amd64) export CC="${CC_WINDOWS_AMD64:-x86_64-w64-mingw32-gcc}" ;;
    linux-amd64)   export CC="${CC:-gcc}" ;;
  esac

  go build -buildmode=c-shared -o "$OUTFILE" .
  echo "[ok] $OUTFILE"
done

unset GOOS GOARCH CGO_ENABLED CC

echo "[build] preparing server.js"
cp ./server.src.js ./server.js
echo "[ok] server.js"

rm -f "$ZIP_OUT"

ZIP_SOURCES=()
for target in $BUILD_TARGETS; do
  TARGET_OS="${target%%-*}"
  TARGET_ARCH="${target#*-}"
  case "$TARGET_OS" in
    windows) ZIP_SOURCES+=("$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.dll") ;;
    darwin)  ZIP_SOURCES+=("$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.dylib") ;;
    *)       ZIP_SOURCES+=("$PLUGIN_NAME-$TARGET_OS-$TARGET_ARCH.so") ;;
  esac
done

ZIP_SOURCES+=("$PLUGIN_NAME.html" "$PLUGIN_NAME.css" "$PLUGIN_NAME.js" "config.json" "server.js")

zip -j "$ZIP_OUT" "${ZIP_SOURCES[@]}"

echo "[ok] $ZIP_OUT"
