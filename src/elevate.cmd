@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
rem
rem Reopen a bat file as administrator when it was started without administrator rights.
rem   call "%~dp0..\src\elevate.cmd" "%~f0" || exit /b
rem Returns errorlevel 0 when the window already has administrator rights.  Otherwise it starts
rem the bat file again through User Account Control and returns errorlevel 1, so the caller ends.
"%SystemRoot%\System32\net.exe" session >nul 2>nul
if not errorlevel 1 exit /b 0
echo.
echo  Reopening as administrator. Click [Yes] in the User Account Control window.
echo  (If it asks for an administrator password, sign in with an administrator account.)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath '%~f1' -Verb RunAs"
exit /b 1
