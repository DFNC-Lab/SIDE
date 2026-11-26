@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
rem Preview what the verifier will see.  Runs verifier\2_check_package.bat with this folder's seal_pub.hex.
if exist "%~dp0seal_pub.hex" set SIDE_PUB=%~dp0seal_pub.hex
call "%~dp0..\verifier\2_check_package.bat"
