@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
rem
rem Shared runner for the bat files in organization\, employee\ and verifier\.
rem   call "%~dp0..\src\run.cmd" <role> <command> [arguments]
rem It finds Python 3.10 or later, asks for administrator rights for the employee role,
rem runs side.py with the arguments, reports the result and waits for a key.
chcp 65001 >nul
call "%~dp0find_python.cmd"
if not defined PY exit /b 1
if /i not "%~1"=="employee" goto run
call "%~dp0require_admin.cmd"
if errorlevel 1 exit /b 2
:run
%PY% "%~dp0..\side.py" %*
set SIDE_RC=%errorlevel%
echo.
if "%SIDE_RC%"=="0" echo  Done.
if not "%SIDE_RC%"=="0" echo  Finished with exit code %SIDE_RC%. Read the messages above.
echo.
pause
exit /b %SIDE_RC%
