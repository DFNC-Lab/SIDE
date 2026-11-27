@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
if exist "%~dp0lib\run.cmd" goto side_ok
echo  ! The lib\ folder is missing in %~dp0
echo    Copy the whole folder, including lib\, and run the file inside it.
echo.
echo  Press any key to close this window.
pause >nul
exit /b 1
:side_ok
title SIDE 3 - make a disclosure package
echo ============================================================
echo   SIDE make a disclosure package - the incident records only
echo ============================================================
echo.
echo  The package holds hashes and proofs, not conversation text.
echo  [1] Package only (default)
echo  [2] Package and the text of the chosen lines (.lines.jsonl)
echo      (needs a collection made with session logs)
echo.
set MODE=
set /p MODE=Choose 1 or 2 :
if "%MODE%"=="2" goto with_lines
call "%~dp0lib\run.cmd" organization disclose
exit /b
:with_lines
call "%~dp0lib\run.cmd" organization disclose --lines
