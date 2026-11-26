@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
rem Opens the viewer window without a console window.
chcp 65001 >nul
call "%~dp0..\src\find_python.cmd" windowed
if not defined PY exit /b 1
start "" %PY% "%~dp0..\side.py" verifier
