@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
rem Reopens the calling bat file as administrator through User Account Control.
rem Usage: call elevate.cmd "%~f0" || exit /b
"%SystemRoot%\System32\net.exe" session >nul 2>nul
if not errorlevel 1 exit /b 0
set "SIDE_SELF=%~f1"
set "SIDE_SELF=%SIDE_SELF:'=''%"
echo.
echo  Reopening as administrator. Click [Yes] in the User Account Control window.
echo  (If it asks for an administrator password, sign in with an administrator account.)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "try { Start-Process -FilePath '%SIDE_SELF%' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
if not errorlevel 1 exit /b 1
echo.
echo  ! The administrator window did not open (User Account Control was cancelled or refused).
echo    Nothing was done. Run the bat file again and click [Yes].
echo    If the folder is on a network drive, copy it to a local drive first.
echo.
echo  Press any key to close this window.
pause >nul
exit /b 1
