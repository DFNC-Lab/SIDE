@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
title SIDE 2 - receive a collection
echo ============================================================
echo   SIDE receive a collection - compare, sign the seal, verify
echo ============================================================
echo.
echo  Drag a file or folder onto this window to enter its path, then press Enter.
echo.
set ZIP=
set KEEP=
set SECRET=
set /p ZIP=Received collection (SIDE_collection_*.zip) :
set /p KEEP=Custody folder of that device (SIDE_custody_*) :
if not defined ZIP goto missing
if not defined KEEP goto missing
set ZIP=%ZIP:"=%
set KEEP=%KEEP:"=%
if exist "%~dp0org_keys\seal_secret.hex" set SECRET=%~dp0org_keys\seal_secret.hex
if defined SECRET goto have_secret
set /p SECRET=Seal private key file (seal_secret.hex) :
if not defined SECRET goto missing
set SECRET=%SECRET:"=%
:have_secret
call "%~dp0..\src\run.cmd" organization receive "%ZIP%" --custody "%KEEP%" --seal-private-key "%SECRET%"
exit /b
:missing
echo.
echo  ! A path was left empty. Nothing was done.
echo.
pause
exit /b 1
