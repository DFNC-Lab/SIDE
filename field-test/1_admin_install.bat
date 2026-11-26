@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
cd /d "%~dp0"
title SIDE test 1 -- administrator install
net session >nul 2>nul
if not errorlevel 1 goto admin_ok
echo.
echo  Reopening as administrator. Click [Yes] in the User Account Control window.
echo  (If it asks for an administrator password, this account is not an administrator.
echo   Log in with an administrator account.)
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b
:admin_ok
call "%~dp0..\src\find_python.cmd" allusers quiet
if defined PY goto py_ok
echo.
echo  Python 3.10 or later for all users was not found (%ProgramFiles%\Python3xx).
echo  SIDE does not use a Python in a user folder, because the employee could change it.
where winget >nul 2>nul
if errorlevel 1 goto no_py
echo  Installing Python 3.13 for all users with winget. This takes a few minutes...
winget install -e --id Python.Python.3.13 --scope machine --silent --accept-package-agreements --accept-source-agreements
call "%~dp0..\src\find_python.cmd" allusers quiet
if defined PY goto py_ok
:no_py
echo.
echo  The automatic install did not work. On the python.org page that opens, download the
echo  Windows installer (64-bit) and install it with
echo    Customize installation - Next - check "Install Python for all users" - Install
echo  Then run this file again.
start "" https://www.python.org/downloads/windows/
pause
exit /b 1
:py_ok
echo  Python: %PY%
"%PY%" -I -X utf8 "%~dp0side_test.py" install
echo.
echo  Press any key to close this window.
pause >nul
