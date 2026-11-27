@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
rem Sets PY to a Python 3.10 or later.  Modes: (none) py or python on PATH, windowed (pyw),
rem allusers (Program Files only, for the SYSTEM service), allusers quiet (no message).
set PY=
if /i "%~1"=="windowed" goto windowed
if /i "%~1"=="allusers" goto allusers
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set PY=py -3
if defined PY exit /b 0
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set PY=python
if defined PY exit /b 0
echo Could not find Python 3.10 or later.
echo Install it from python.org and tick "Add Python to PATH" on the first screen.
echo  Press any key to close this window.
pause >nul
exit /b 1
:windowed
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set PY=pyw -3
if defined PY exit /b 0
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set PY=pythonw
if defined PY exit /b 0
echo Could not find Python 3.10 or later.
echo Install it from python.org and tick "Add Python to PATH" on the first screen.
echo  Press any key to close this window.
pause >nul
exit /b 1
:allusers
for /d %%D in ("%ProgramFiles%\Python3*") do (
  "%%D\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=%%D\python.exe"
)
if defined PY exit /b 0
if /i "%~2"=="quiet" exit /b 1
echo.
echo  Python 3.10 or later for all users was not found (%ProgramFiles%\Python3xx\python.exe).
echo  A Python in a user folder (the python.org default) cannot run the SYSTEM service.
echo  Install it from python.org: Windows installer (64-bit), Customize installation,
echo  tick "Install Python for all users", then run the bat file again.
echo.
echo  Press any key to close this window.
pause >nul
exit /b 1
