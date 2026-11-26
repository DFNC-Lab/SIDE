@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
call "%~dp0..\src\elevate.cmd" "%~f0" || exit /b
title SIDE 2 - move the root key
echo ============================================================
echo   SIDE move the root key K0 off the device
echo   Run this only if the root key was not moved during install.
echo ============================================================
echo.
echo  Drag the destination folder (a USB drive, for example) onto this window, then press Enter.
echo.
set KEY=
set /p KEY=Destination folder :
if not defined KEY goto ask_later
set KEY=%KEY:"=%
call "%~dp0..\src\run.cmd" employee root-key --key-out "%KEY%"
exit /b
:ask_later
call "%~dp0..\src\run.cmd" employee root-key
