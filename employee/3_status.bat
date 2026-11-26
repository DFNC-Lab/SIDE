@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
call "%~dp0..\src\elevate.cmd" "%~f0" || exit /b
title SIDE 3 - status
call "%~dp0..\src\run.cmd" employee status
