@echo off
REM Builds every plugin in the suite into its own .zip.
REM Each plugin is independent: its own DLL, its own server.js, its own zip.

setlocal enabledelayedexpansion

set "PLUG_ROOT=%~dp0"
if not "%~1"=="" set "PLUG_ROOT=%~1"

set "PLUGINS=whisper mimik lanmap worm mitm router iot admap dcsync respool aitm evasion privsec"

echo ============================================================
echo  Building Overlord plugin suite
echo  root: %PLUG_ROOT%
echo ============================================================
echo.

set /a BUILT=0
set /a FAILED=0

for %%P in (%PLUGINS%) do (
  call :buildone %%P
)

echo ============================================================
echo  Built: !BUILT!   Failed: !FAILED!
echo ============================================================
echo.
echo Zips produced:
for %%P in (%PLUGINS%) do (
  if exist "%PLUG_ROOT%%%P\%%P.zip" (
    for %%F in ("%PLUG_ROOT%%%P\%%P.zip") do echo   %%~nxF   %%~zF bytes
  )
)
echo.
echo Upload each .zip from the Plugins page, or drop them into
echo Overlord-Server\plugins\ and restart the server.
goto :eof

:buildone
set "P=%~1"
echo ------------------------------------------------------------
echo  [!P!]
echo ------------------------------------------------------------
if not exist "%PLUG_ROOT%!P!\build.bat" (
  echo   [skip] no build.bat
  echo.
  goto :eof
)
pushd "%PLUG_ROOT%!P!"
call build.bat
if errorlevel 1 (
  echo   [FAIL] !P!
  set /a FAILED+=1
) else (
  echo   [ok] !P!
  set /a BUILT+=1
)
popd
echo.
goto :eof
