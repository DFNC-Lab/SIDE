@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
title SIDE check a disclosure package
echo ============================================================
echo   SIDE check a disclosure package (command window)
echo ============================================================
echo.
echo  Drag a file onto this window to enter its path, then press Enter.
echo.
set PKG=
set PUB=%SIDE_PUB%
set LINES=
set /p PKG=Disclosure package (SIDE_disclosure_*.json) :
if not defined PKG goto missing
set PKG=%PKG:"=%
if not defined PUB if exist "%~dp0seal_pub.hex" set PUB=%~dp0seal_pub.hex
if defined PUB goto have_pub
set /p PUB=Seal public key file (seal_pub.hex) or its 64-digit value :
if not defined PUB goto missing
set PUB=%PUB:"=%
:have_pub
echo  Seal public key: %PUB%
for %%F in ("%PKG%") do if exist "%%~dpnF.lines.jsonl" set LINES=%%~dpnF.lines.jsonl
if defined LINES goto with_lines
call "%~dp0..\src\run.cmd" verifier check "%PKG%" --seal-public-key "%PUB%"
exit /b
:with_lines
echo  Line text      : %LINES%
call "%~dp0..\src\run.cmd" verifier check "%PKG%" --seal-public-key "%PUB%" --lines "%LINES%"
exit /b
:missing
echo.
echo  ! A path was left empty. Nothing was done.
echo.
pause
exit /b 1
