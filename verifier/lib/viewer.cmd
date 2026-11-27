@echo off
rem SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
rem SPDX-License-Identifier: Apache-2.0
rem Opens the viewer window without a console window.
call "%~dp0find_python.cmd" windowed
if not defined PY exit /b 1
%PY% -c "import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if not errorlevel 1 goto open
echo.
echo  ! The viewer needs Python 3.10 or later with tcl/tk.
echo    Rerun the python.org installer (Modify) and turn on "tcl/tk and IDLE",
echo    or use 2_check_package.bat (verifier) or 4_verify_package.bat (organization), which need no window.
echo.
echo  Press any key to close this window.
pause >nul
exit /b 1
:open
start "" %PY% "%~dp0side.py" verifier
