@echo off
setlocal enabledelayedexpansion

set "GOWORK=off"
set "PLUGIN_DIR=%~dp0"
set "NATIVE_DIR=%PLUGIN_DIR%native"
set "GATEWAY_DIR=%PLUGIN_DIR%gateway"
set "PLUGIN_NAME=respool"
set "ZIP_OUT=%PLUGIN_DIR%%PLUGIN_NAME%.zip"

if not defined BUILD_TARGETS set "BUILD_TARGETS=windows-amd64"

echo [build] gateway (standalone, runs on the VPS)
pushd "%GATEWAY_DIR%"
if not exist "go.mod" go mod init respoolgateway >nul 2>&1
set "CGO_ENABLED=0"
set "GOOS="
set "GOARCH="
go build -o "%PLUGIN_DIR%respool-gateway.exe" .
if errorlevel 1 (
  echo [error] gateway build failed
  popd
  exit /b 1
)
echo [ok] respool-gateway.exe
popd

pushd "%NATIVE_DIR%"

for %%T in (%BUILD_TARGETS%) do (
  for /f "tokens=1,2 delims=-" %%A in ("%%T") do (
    set "TARGET_OS=%%A"
    set "TARGET_ARCH=%%B"
  )

  set "EXT=so"
  if "!TARGET_OS!"=="windows" set "EXT=dll"
  if "!TARGET_OS!"=="darwin" set "EXT=dylib"

  set "OUTFILE=%PLUGIN_DIR%%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.!EXT!"

  echo [build] GOOS=!TARGET_OS! GOARCH=!TARGET_ARCH!
  set "GOOS=!TARGET_OS!"
  set "GOARCH=!TARGET_ARCH!"
  set "CGO_ENABLED=1"
  if "!TARGET_OS!"=="windows" set "CC=gcc"

  go build -buildmode=c-shared -o "!OUTFILE!" .
  if errorlevel 1 (
    echo [error] build failed for !TARGET_OS!-!TARGET_ARCH!
    popd
    exit /b 1
  )
  echo [ok] !OUTFILE!
)

set "GOOS="
set "GOARCH="
set "CGO_ENABLED="
set "CC="

popd

echo [build] preparing server.js
copy /y "%PLUGIN_DIR%server.src.js" "%PLUGIN_DIR%server.js" >nul
echo [ok] server.js

if exist "%ZIP_OUT%" del /f /q "%ZIP_OUT%"

set "BINLIST="
for %%T in (%BUILD_TARGETS%) do (
  for /f "tokens=1,2 delims=-" %%A in ("%%T") do (
    set "TARGET_OS=%%A"
    set "TARGET_ARCH=%%B"
  )
  set "EXT=so"
  if "!TARGET_OS!"=="windows" set "EXT=dll"
  if "!TARGET_OS!"=="darwin" set "EXT=dylib"
  set "BINLIST=!BINLIST! %PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.!EXT!"
)

REM The gateway ships inside the zip as a helper binary.
set "BINLIST=!BINLIST! respool-gateway.exe"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$d='%PLUGIN_DIR%'.TrimEnd('\'); $n='%PLUGIN_NAME%'; $bins='%BINLIST%'.Trim(); $files=@($bins -split ' ' | Where-Object { $_ } | ForEach-Object { Join-Path $d $_ }); $files += @((Join-Path $d ($n+'.html')),(Join-Path $d ($n+'.css')),(Join-Path $d ($n+'.js')),(Join-Path $d 'config.json'),(Join-Path $d 'server.js')); $files = $files | Where-Object { Test-Path $_ }; Compress-Archive -Path $files -DestinationPath (Join-Path $d ($n+'.zip')) -Force"
if errorlevel 1 (
  echo [error] zip creation failed
  exit /b 1
)

echo [ok] %ZIP_OUT%
