@echo off
setlocal
cd /d "%~dp0"

REM ---- 选 python：优先项目内 .venv，其次 Hermes 自带 venv，最后 PATH 上的 python ----
set "PY="
if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\hermes\hermes-agent\venv\Scripts\python.exe" set "PY=%LOCALAPPDATA%\hermes\hermes-agent\venv\Scripts\python.exe"
if not defined PY set "PY=python"

REM ---- 抓候选名单和 git push 需要走代理；mihomo 拨号由脚本内部剥离代理环境变量 ----
set "HTTPS_PROXY=http://127.0.0.1:3067"
set "HTTP_PROXY=http://127.0.0.1:3067"

REM ---- 校验参数 ----
set "DELAY_TIMEOUT_MS=3500"
set "CONCURRENCY=160"
set "HTTP_LIMIT=2000"

echo [%DATE% %TIME%] start, python=%PY% >> verify.log
"%PY%" verify_cn.py >> verify.log 2>&1
echo [%DATE% %TIME%] end, exit=%ERRORLEVEL% >> verify.log
endlocal
