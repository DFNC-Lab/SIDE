@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
cd /d "%~dp0"
title SIDE test 2 -- employee
rem This file runs from C:\Users\Public\SIDE_test without src\, so it keeps its own Python search.
set "PY="
for /d %%D in ("%ProgramFiles%\Python3*") do (
  "%%D\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=%%D\python.exe"
)
if defined PY goto py_ok
echo.
echo  Python 3.10 or later for all users was not found (%ProgramFiles%\Python3xx\python.exe).
echo  Run 1_admin_install.bat from the administrator account first. It installs Python.
echo.
pause
exit /b 1
:py_ok
echo  Python: %PY%
"%PY%" -I -X utf8 "%~dp0side_test.py" employee
echo.
echo  Press any key to close this window.
pause >nul
