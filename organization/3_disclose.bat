@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
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
call "%~dp0..\src\run.cmd" organization disclose
exit /b
:with_lines
call "%~dp0..\src\run.cmd" organization disclose --lines
