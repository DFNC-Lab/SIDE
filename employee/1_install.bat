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
title SIDE 1 - install
echo ============================================================
echo   SIDE install - the binding service starts under the SYSTEM account
echo ============================================================
echo.
echo  Before you start:
echo    - seal_pub.hex from the organization is in this folder
echo    - Python 3.10 or later is installed "for all users"
echo    - a USB drive for the root key is plugged in (you type its folder, for example E:\)
echo.
if exist "%~dp0seal_pub.hex" goto have_pub
if exist "%~dp0seal_pub.key" goto have_pub
echo  ! seal_pub.hex is not in %~dp0
echo    Get it from the organization (organization\1_make_seal_key.bat) and run this file again.
echo.
echo  Press any key to close this window.
pause >nul
exit /b 1
:have_pub
set EMP=
set /p EMP=Employee account to bind (Enter = the account signed in now) :
if not defined EMP goto signed_in
set "EMP=%EMP:"=%"
call "%~dp0lib\run.cmd" employee install --employee "%EMP%"
exit /b
:signed_in
call "%~dp0lib\run.cmd" employee install
