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
call "%~dp0lib\elevate.cmd" "%~f0" || exit /b
title SIDE 9 - uninstall
echo ============================================================
echo   SIDE uninstall - stop the service. The records stay.
echo ============================================================
echo.
echo  Binding stops until the next install. To hand the records over, run 4_collect.bat instead.
echo.
set OK=
set /p OK=Type Y to stop the service :
if /i "%OK%"=="Y" goto stop
echo.
echo  Nothing was done. The service keeps running.
echo.
echo  Press any key to close this window.
pause >nul
exit /b 1
:stop
call "%~dp0lib\run.cmd" employee uninstall
