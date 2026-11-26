@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
call "%~dp0..\src\elevate.cmd" "%~f0" || exit /b
title SIDE 4 - collect
echo ============================================================
echo   SIDE collect - stop the service, seal the chains, pack one zip
echo ============================================================
echo.
echo  After the seal, nothing more is bound into this service folder.
echo  To keep recording, run 1_install.bat again after the collection.
echo.
echo  [1] Chains only - no conversation text (default)
echo  [2] Chains and session logs - includes the conversation text
echo      (the organization can then rerun every check and disclose line text)
echo.
set MODE=
set /p MODE=Choose 1 or 2 :
if "%MODE%"=="2" goto with_logs
call "%~dp0..\src\run.cmd" employee collect
exit /b
:with_logs
call "%~dp0..\src\run.cmd" employee collect --include-logs
