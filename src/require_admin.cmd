@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
rem Return errorlevel 0 in a window with administrator rights.  Otherwise explain, pause and
rem return errorlevel 2.  The bat files of employee\ call it before they run side_device.py.
"%SystemRoot%\System32\net.exe" session >nul 2>nul
if not errorlevel 1 exit /b 0
echo Administrator rights are required. Run the bat file again and click Yes in User Account Control.
pause
exit /b 2
