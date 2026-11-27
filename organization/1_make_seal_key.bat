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
title SIDE 1 - make the seal key pair
echo ============================================================
echo   SIDE make the seal key pair (once, on the organization PC)
echo ============================================================
echo.
echo  org_keys\seal_secret.hex  private key - never let it leave this PC
echo  seal_pub.hex              public key  - give it to each employee PC and publish it to verifiers
echo.
call "%~dp0lib\run.cmd" organization seal-key
