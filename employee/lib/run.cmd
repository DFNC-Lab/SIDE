@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
rem Shared runner for the role bat files: finds Python (Program Files only for the employee role),
rem runs side.py with the arguments and waits for a key.  Usage: call run.cmd <role> <command> ...
if /i "%~1"=="employee" goto employee
call "%~dp0find_python.cmd"
if not defined PY exit /b 1
goto run
:employee
call "%~dp0find_python.cmd" allusers
if not defined PY exit /b 1
set PY="%PY%"
:run
%PY% "%~dp0side.py" %*
set SIDE_RC=%errorlevel%
echo.
if "%SIDE_RC%"=="0" echo  Done.
if not "%SIDE_RC%"=="0" echo  Finished with exit code %SIDE_RC%. Read the messages above.
echo.
echo  Press any key to close this window.
pause >nul
exit /b %SIDE_RC%
