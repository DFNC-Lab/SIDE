@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
cd /d "%~dp0"
title SIDE test diagnosis
call "%~dp0..\employee\lib\elevate.cmd" "%~f0" || exit /b
call "%~dp0..\employee\lib\find_python.cmd" allusers
if not defined PY exit /b 1
echo  Python: %PY%
"%PY%" -I -X utf8 "%~dp0side_test.py" diagnose
echo.
echo  Press any key to close this window.
pause >nul
