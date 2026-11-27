@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
cd /d "%~dp0"
title SIDE test 1 -- administrator install
call "%~dp0..\employee\lib\elevate.cmd" "%~f0" || exit /b
call "%~dp0..\employee\lib\find_python.cmd" allusers quiet
if defined PY goto py_ok
echo.
echo  Python 3.10 or later for all users was not found (%ProgramFiles%\Python3xx).
echo  SIDE does not use a Python in a user folder, because the employee could change it.
where winget >nul 2>nul
if errorlevel 1 goto no_py
echo  Installing Python 3.13 for all users with winget. This takes a few minutes...
winget install -e --id Python.Python.3.13 --scope machine --silent --accept-package-agreements --accept-source-agreements
call "%~dp0..\employee\lib\find_python.cmd" allusers quiet
if defined PY goto py_ok
:no_py
echo.
echo  The automatic install did not work. On the python.org page that opens, download the
echo  Windows installer (64-bit) and install it with
echo    Customize installation - Next - check "Install Python for all users" - Install
echo  Then run this file again.
start "" https://www.python.org/downloads/windows/
echo  Press any key to close this window.
pause >nul
exit /b 1
:py_ok
echo  Python: %PY%
"%PY%" -I -X utf8 "%~dp0side_test.py" install
echo.
echo  Press any key to close this window.
pause >nul
