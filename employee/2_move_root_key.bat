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
title SIDE 2 - move the root key
echo ============================================================
echo   SIDE move the root key K0 off the device
echo   Run this only if the root key was not moved during install.
echo ============================================================
echo.
echo  Type the destination folder (a USB drive, for example E:\), then press Enter.
echo  Dragging a folder onto this window does not work, because it runs as administrator.
echo.
set KEY=
set /p KEY=Destination folder :
if not defined KEY goto ask_later
set "KEY=%KEY:"=%"
if "%KEY:~-1%"=="\" set "KEY=%KEY%."
call "%~dp0lib\run.cmd" employee root-key --key-out "%KEY%"
exit /b
:ask_later
call "%~dp0lib\run.cmd" employee root-key
