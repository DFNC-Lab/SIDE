@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
rem SPDX-License-Identifier: Apache-2.0
rem Set PY to a Python 3.10 or later.  Without one, print why and return errorlevel 1.
rem   call find_python.cmd                 py launcher or python on PATH
rem   call find_python.cmd windowed        pyw launcher or pythonw on PATH (no console window)
rem   call find_python.cmd allusers        python.exe under Program Files only
rem   call find_python.cmd allusers quiet  the same without the message
rem The allusers mode ignores a Python under a user folder, because its owner could change it.
set PY=
if /i "%~1"=="windowed" goto windowed
if /i "%~1"=="allusers" goto allusers
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set PY=py -3
if defined PY exit /b 0
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set PY=python
if defined PY exit /b 0
echo Could not find Python 3.10 or later.
echo Install it from python.org and tick "Add Python to PATH" on the first screen.
pause
exit /b 1
:windowed
pyw -3 -c "import sys" >nul 2>nul && set PY=pyw -3
if defined PY exit /b 0
where pythonw >nul 2>nul && set PY=pythonw
if defined PY exit /b 0
echo Python 3.10 or later was not found. Install it from python.org.
pause
exit /b 1
:allusers
for /d %%D in ("%ProgramFiles%\Python3*") do (
  "%%D\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=%%D\python.exe"
)
if defined PY exit /b 0
if /i "%~2"=="quiet" exit /b 1
echo.
echo  Python 3.10 or later for all users was not found (%ProgramFiles%\Python3xx\python.exe).
echo  Run 1_admin_install.bat from the administrator account first. It installs Python.
echo.
pause
exit /b 1
