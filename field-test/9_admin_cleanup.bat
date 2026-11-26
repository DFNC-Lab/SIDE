@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
cd /d "%~dp0"
title SIDE test cleanup
net session >nul 2>nul
if not errorlevel 1 goto admin_ok
echo.
echo  Reopening as administrator. Click [Yes] in the User Account Control window.
echo  (If it asks for an administrator password, this account is not an administrator.
echo   Log in with an administrator account.)
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b
:admin_ok
call "%~dp0..\src\find_python.cmd" allusers
if not defined PY exit /b 1
echo  Python: %PY%
"%PY%" -I -X utf8 "%~dp0side_test.py" cleanup
echo.
echo  Press any key to close this window.
pause >nul
