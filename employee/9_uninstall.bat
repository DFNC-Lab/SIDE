@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
call "%~dp0..\src\elevate.cmd" "%~f0" || exit /b
title SIDE 9 - uninstall
echo ============================================================
echo   SIDE uninstall - stop the service. The records stay.
echo ============================================================
echo.
echo  Binding stops until the next install. To hand the records over, run 4_collect.bat instead.
echo.
set OK=
set /p OK=Type Y to stop the service :
if /i not "%OK%"=="Y" exit /b 1
call "%~dp0..\src\run.cmd" employee uninstall
