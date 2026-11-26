@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
chcp 65001 >nul
title SIDE 1 - make the seal key pair
echo ============================================================
echo   SIDE make the seal key pair (once, on the organization PC)
echo ============================================================
echo.
echo  org_keys\seal_secret.hex  private key - never let it leave this PC
echo  seal_pub.hex              public key  - give it to each employee PC and publish it to verifiers
echo.
call "%~dp0..\src\run.cmd" organization seal-key
