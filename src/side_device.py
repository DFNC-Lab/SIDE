# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
# SPDX-License-Identifier: Apache-2.0
r"""SIDE device administration: install, move the root key, status, collect, uninstall.

The tool runs the binding service (side_service.py) as a permanent service under SYSTEM.

  * The tool copies the service modules to %ProgramData%\SIDE\bin and locks that folder.  If
    SYSTEM ran code from a folder the employee can write, the employee could change that code and
    run it as SYSTEM.
  * The tool refuses a Python under a user profile or from the Microsoft Store for the same
    reason.  The service starts Python with -I, so Python ignores environment variables and user
    site-packages.
  * A scheduled task under SYSTEM starts the service at boot, keeps it running on battery and sets
    no run time limit.  The employee cannot open the service folder or stop the service.
  * SYSTEM creates the service folder itself and locks it to SYSTEM and Administrators before the
    service starts.
  * Enrollment accepts only a seal public key that the organization made off the device
    (--seal-pubkey).  The seal private key never exists on the device.  The device creates the
    root key K0 and writes it to the locked organization folder.  K0 never appears on screen or in
    a log the employee can read.
  * The stop file lives in the locked organization folder.  When the process dies, the batch loop
    starts it again.
  * The service sweeps the session logs of Claude Code, Codex CLI and Antigravity.  It also
    watches tools that have no session logs yet, so a tool installed later is bound from then on.
  * Right after enrollment the administrator moves K0 off the device, and the tool erases the
    device copy.  Until then, anyone who copies K0 can recompute every tag.

Usage (all commands need administrator rights)
    python side.py employee install [--employee <account>] [--key-out <folder>] [--fresh]
    python side.py employee root-key --key-out <folder>      if install skipped this step
    python side.py employee status
    python side.py employee collect [--include-logs] [--out <folder>]
    python side.py employee uninstall

The employee bundle folder (employee\ next to src\) holds seal_pub.hex and receives collections\.

Design notes
  * Enrollment runs only when none exists.  A new enrollment makes a new K0, and the chains bound
    earlier would no longer verify.  So install continues in an unsealed service folder.  A sealed
    folder or --fresh moves the previous install aside.
  * The service always reads in backup mode.  In auto mode, a failure to enable the backup
    privilege would fall back silently to a plain open.  In backup mode the service refuses to
    start, and restart.log records it.  Python runs unbuffered (-u), so service.log shows where a
    service stalled.
  * The task runs at priority 4 (normal, like interactive programs).  The default priority 7 also
    lowers the process and disk I/O priority, and after boot that delays the service by minutes.
  * The batch loop restarts the service process.  The task restart count (one minute apart) is
    only an outer safety net for when watch.cmd itself fails.
  * The tool stops the service with the stop file.  A killed service writes no service_stop record,
    and the verifier reads that as an abnormal stop.  So the tool kills only when the stop file has
    no effect.
  * A service that starts late after boot deletes the stop file as a leftover from the last run.
    So the tool writes the stop file again while it waits.
  * The process search excludes PowerShell itself.  Its command line holds the search text, so an
    absent service would otherwise count as one.
  * K0 on the device is overwritten, then deleted.  On an SSD the overwrite may not reach the
    original blocks.  The deletion always runs.
  * Compatibility: a service folder from an older install holds seal_pub.key.  The collection
    archive always names the key seal_pub.hex.  Session log copies in the archive are named by
    source_key, which --sessions-dir uses to find them.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import time
import zipfile

SRC = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))

import side_bind as bind
import side_core as core
import side_store as store
import side_util as util
import side_verify as verify
from side_util import say

HERE = SRC.parent / "employee"
SERVICE_NAME = "side_service.py"
CORE_NAME = "side_core.py"
RUNTIME = (CORE_NAME, "side_store.py", "side_bind.py", "side_verify.py", "side_util.py", SERVICE_NAME)
REVISION_EXPECTED = core.REVISION
SEAL_PUB_NAME = core.SEAL_PUB_NAME
ENROLL_NAME = core.ENROLL_NAME

TASK = "SIDE"
BASE = pathlib.Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SIDE"
BIN = BASE / "bin"
STORE = BASE / "store"
ORG = BASE / "org"
ORGKEY = ORG / core.K0_NAME
SEAL_PUB = ORG / SEAL_PUB_NAME
ENROLL_LOG = ORG / "enroll.log"
STOPFILE = ORG / "STOP"
WATCH_CMD = BIN / "watch.cmd"
RESTART_LOG = BASE / "restart.log"
SERVICE_LOG = BASE / "service.log"
WHO = BASE / "whoami.txt"
STORE_ACL_LOG = BASE / "store_acl.txt"
INSTALL_RECORD = BASE / "install.json"
DEVICE = STORE / core.CHAINS_DIR / core.LEDGER_NAME
KEYS = STORE / "keys"

RESTART_ON_ERROR = 5
MAX_RESTARTS = 1000
RESTART_PAUSE_PINGS = 11
TASK_RESTART_COUNT = 999
TASK_PRIORITY = 4
STOP_WAIT_SEC = 900
STOP_PROGRESS_SEC = 30
ENROLL_WAIT_SEC = 60
RESUME_WAIT_SEC = 5
KILL_WAIT_SEC = 2
MIN_WIPE_BYTES = 64
RULE = util.RULE


def run(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, encoding="mbcs",
                          errors="replace", **kw)


def ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([util.POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def ps_utf8(script: str) -> str:
    r = ps("[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script)
    return (r.stdout or "").strip()


def is_admin() -> bool:
    return run([util.NET, "session"]).returncode == 0


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def banner(title: str) -> None:
    say("=" * RULE)
    say("  " + title)
    say("=" * RULE)


def lock_down(path: pathlib.Path) -> None:
    r = util.lock_folder(path)
    if r.returncode:
        raise SystemExit("Could not lock the folder: %s\n%s" % (path, (r.stdout or "") + (r.stderr or "")))


def check_python() -> pathlib.Path:
    exe = pathlib.Path(sys.executable).resolve()
    if exe.name.lower() == "pythonw.exe":
        exe = exe.with_name("python.exe")
    if sys.version_info < (3, 10):
        raise SystemExit("Python 3.10 or later is required (this is %s)." % sys.version.split()[0])
    lower = str(exe).lower()
    users_dir = str(pathlib.Path(os.environ.get("SystemDrive", "C:") + "\\Users")).lower()
    if "windowsapps" in lower:
        raise SystemExit("This Python comes from the Microsoft Store.  SYSTEM cannot run it.\n"
                         "Reinstall Python from the python.org installer and choose 'Install for all users'.")
    if lower.startswith(users_dir):
        raise SystemExit("Python lives under a user folder: %s\n"
                         "The owner of that folder can replace python.exe and run code as SYSTEM.\n"
                         "Install Python into Program Files with the python.org installer\n"
                         "('Install for all users'), then run this file with that Python." % exe)
    return exe


def console_user() -> str:
    return ps_utf8("(Get-CimInstance Win32_ComputerSystem).UserName")


def profile_path(account: str) -> pathlib.Path:
    q = account.replace("'", "''")
    out = ps_utf8(
        "$sid=(New-Object System.Security.Principal.NTAccount('%s'))"
        ".Translate([System.Security.Principal.SecurityIdentifier]).Value; "
        "(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath" % q)
    if not out:
        raise SystemExit("Could not find the profile folder of account '%s'.  Sign in to that account once\n"
                         "and install again, or give the exact account name with --employee." % account)
    return pathlib.Path(out.splitlines()[0].strip())


def session_patterns(home: pathlib.Path) -> list[str]:
    return [str(home / pat[2:]) for pats in bind.SOURCES.values() for pat in pats]


def task_exists() -> bool:
    return run([util.SCHTASKS, "/Query", "/TN", TASK]).returncode == 0


def _service_processes(action: str) -> str:
    return ps_utf8("@(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID "
                   "-and $_.Name -like 'python*' -and $_.CommandLine -like '*%s*--watch*' "
                   "-and $_.CommandLine -like '*\\SIDE\\bin\\*' })%s" % (SERVICE_NAME, action))


def service_count() -> int:
    try:
        return int(_service_processes(".Count") or "0")
    except ValueError:
        return 0


def kill_service() -> int:
    out = _service_processes(" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; 'killed' }")
    return out.count("killed")


def stop_service(max_seconds: int = STOP_WAIT_SEC) -> bool:
    normal = True
    if service_count():
        STOPFILE.write_text("stop", encoding="utf-8")
        normal = False
        for i in range(max_seconds):
            time.sleep(1)
            if not service_count():
                normal = True
                break
            if not STOPFILE.exists():
                try:
                    STOPFILE.write_text("stop", encoding="utf-8")
                    say("  The stop file disappeared and was written again (the starting service removed it)")
                except OSError:
                    pass
            if i % STOP_PROGRESS_SEC == STOP_PROGRESS_SEC - 1:
                say("  Waiting for the service to finish its current sweep (%d s)" % (i + 1))
        if not normal:
            say("  The stop file had no effect.  Ending the service by force "
                "(the ledger records an abnormal stop).")
            run([util.SCHTASKS, "/End", "/TN", TASK])
            time.sleep(KILL_WAIT_SEC)
            kill_service()
    if task_exists():
        run([util.SCHTASKS, "/End", "/TN", TASK])
        run([util.SCHTASKS, "/Delete", "/TN", TASK, "/F"])
    STOPFILE.unlink(missing_ok=True)
    return normal


def ledger_summary() -> dict:
    try:
        d = json.loads(DEVICE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    ent = d.get("entries", [])
    last = (ent[-1].get("record") or {}) if ent else {}
    return {"records": len(ent), "kind": verify.count_kinds(ent), "last": last.get("kind"),
            "last_time": last.get("ts_recorded"), "seal": bool(d.get("seal"))}


def read_seal_pub() -> str:
    f = store.find_seal_pub(HERE)
    if f is None:
        raise SystemExit("The organization seal public key is missing.\n"
                         "Put the 'seal_pub.hex' that the organization made with "
                         "organization\\1_make_seal_key.bat\n"
                         "into this folder (%s) and run again.\n"
                         "Do not bring the seal private key to the device." % HERE)
    try:
        return store.read_seal_public_key(f)
    except ValueError:
        raise SystemExit("%s does not hold a 64-digit hex value." % f.name) from None


def move_previous_install() -> pathlib.Path | None:
    left = [p for p in (STORE, ORG, BIN, INSTALL_RECORD) if p.exists()]
    if not left:
        return None
    old = BASE.with_name("SIDE_previous_install_%s" % util.now_stamp())
    old.mkdir(parents=True)
    lock_down(old)
    for p in left:
        shutil.move(str(p), str(old / p.name))
    for p in (RESTART_LOG, WHO, STORE_ACL_LOG, SERVICE_LOG):
        if p.exists():
            shutil.move(str(p), str(old / p.name))
    return old


def watch_cmd(py: pathlib.Path, pats: list[str]) -> str:
    def service_cmd(*flags: str) -> str:
        return '"%s" %s "%s"' % (py, " ".join(("-I", "-X", "utf8") + flags), BIN / SERVICE_NAME)
    pattern_args = " ".join('"%s"' % p for p in pats)
    grants = " ".join(util.full_control(util.SID_SYSTEM, util.SID_ADMINS))
    lines = [
        "@echo off",
        "set SIDE_STORE=%s" % STORE,
        '>> "%s" echo %%date%% %%time%% watch.cmd start' % SERVICE_LOG,
        '"%s" > "%s" 2>&1' % (util.WHOAMI, WHO),
        '"%s" /user /fo csv /nh >> "%s" 2>&1' % (util.WHOAMI, WHO),
        'if exist "%s\\" goto storeok' % STORE,
        'mkdir "%s"' % STORE,
        '"%s" "%s" /inheritance:r /grant:r %s > "%s" 2>&1' % (util.ICACLS, STORE, grants, STORE_ACL_LOG),
        ":storeok",
        'if exist "%s" if exist "%s\\" goto enrolled' % (DEVICE, KEYS),
        '%s --enroll --org-out "%s" --seal-pubkey "%s" > "%s" 2>&1'
        % (service_cmd(), ORGKEY, SEAL_PUB, ENROLL_LOG),
        ":enrolled",
        "set /a SIDE_RESTARTS=0",
        ":side_run",
        '>> "%s" echo %%date%% %%time%% python start (restarts=%%SIDE_RESTARTS%%)' % SERVICE_LOG,
        '%s --watch --interval %d --read-mode backup --stopfile "%s" '
        '--restart-on-error %d --patterns %s >> "%s" 2>&1'
        % (service_cmd("-u"), bind.SWEEP_INTERVAL_SEC, STOPFILE, RESTART_ON_ERROR, pattern_args, SERVICE_LOG),
        "set SIDE_RC=%errorlevel%",
        'if exist "%s" goto side_done' % STOPFILE,
        'if "%SIDE_RC%"=="0" goto side_done',
        "set /a SIDE_RESTARTS+=1",
        '>> "%s" echo %%date%% %%time%% exit=%%SIDE_RC%% restart=%%SIDE_RESTARTS%%' % RESTART_LOG,
        "if %%SIDE_RESTARTS%% GEQ %d goto side_done" % MAX_RESTARTS,
        "ping -n %d 127.0.0.1 >nul" % RESTART_PAUSE_PINGS,
        "goto side_run",
        ":side_done",
    ]
    return "\r\n".join(lines) + "\r\n"


def register_task() -> None:
    cmd = str(WATCH_CMD).replace("'", "''")
    r = ps(
        "$ErrorActionPreference='Stop'; "
        "$a=New-ScheduledTaskAction -Execute \"$env:SystemRoot\\System32\\cmd.exe\" -Argument '/c \"%s\"'; "
        "$t=New-ScheduledTaskTrigger -AtStartup; "
        "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew "
        "-RestartCount %d -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -Priority %d; "
        "$p=New-ScheduledTaskPrincipal -UserId '%s' -LogonType ServiceAccount -RunLevel Highest; "
        "Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Settings $s -Principal $p "
        "-Description 'SIDE: AI coding agent session logs binding service' -Force | Out-Null; "
        "Start-ScheduledTask -TaskName '%s'"
        % (cmd, TASK_RESTART_COUNT, TASK_PRIORITY, util.SID_SYSTEM, TASK, TASK))
    if r.returncode:
        raise SystemExit("Could not register the scheduled task:\n" + (r.stdout or "") + (r.stderr or ""))


def install(a) -> int:
    py = check_python()
    pub = read_seal_pub()
    if task_exists() or service_count():
        say("The SIDE service is already running.  To install again, run employee\\9_uninstall.bat first.")
        return 1
    account = a.employee or console_user()
    if not account:
        raise SystemExit("Could not find the employee account signed in now.  "
                         "Give it with --employee <account>.")
    home = profile_path(account)
    pats = session_patterns(home)

    banner("SIDE install")
    say("  Employee account : %s" % account)
    say("  Profile          : %s" % home)
    say("  Python           : %s" % py)
    say("  Service folder   : %s" % STORE)
    say("  Seal public key  : %s…" % pub[:16])
    say("  Binding range    :")
    for p in pats:
        say("      %s" % p)

    resume = DEVICE.exists() and not ledger_summary().get("seal") and not a.fresh
    old = None
    if resume:
        say("\n  An unsealed service folder exists.  Binding continues in it (no new enrollment).")
        if SEAL_PUB.exists() and SEAL_PUB.read_text(encoding="utf-8").strip() != pub:
            raise SystemExit("The seal public key in this folder differs from the one used "
                             "at the last enrollment.\n"
                             "To continue that enrollment, put back the earlier public key.  "
                             "To enroll anew, give --fresh.")
    else:
        old = move_previous_install()
        if old:
            say("\n  The previous install was moved aside, not deleted: %s" % old)

    BASE.mkdir(parents=True, exist_ok=True)
    lock_down(BASE)
    for d in (BIN, ORG):
        d.mkdir(parents=True, exist_ok=True)
    for name in RUNTIME:
        shutil.copy2(SRC / name, BIN / name)
    if REVISION_EXPECTED not in (BIN / CORE_NAME).read_text(encoding="utf-8"):
        raise SystemExit("The service revision is not %s." % REVISION_EXPECTED)
    SEAL_PUB.write_text(pub, encoding="utf-8")
    WATCH_CMD.write_text(watch_cmd(py, pats), encoding="mbcs")
    for d in (BASE, BIN, ORG):
        lock_down(d)

    runtime = {name: util.sha256_file(BIN / name) for name in RUNTIME}
    INSTALL_RECORD.write_text(json.dumps({
        "installed_at_utc": utc_now(),
        "employee": account, "pattern": pats, "python": str(py), "task": TASK,
        "service_sha256": runtime[SERVICE_NAME], "runtime_sha256": runtime,
        "revision": REVISION_EXPECTED, "previous_install": str(old) if old else None},
        ensure_ascii=False, indent=1),
        encoding="utf-8")

    register_task()
    say("\n  Registered and started the scheduled task '%s' under the SYSTEM account "
        "(starts at every boot)." % TASK)
    if resume:
        time.sleep(RESUME_WAIT_SEC)
        say("  Service processes: %d." % service_count())
        return move_root_key(a.key_out, ask=True) if ORGKEY.exists() else 0
    say("  Waiting for enrollment…")
    for _ in range(ENROLL_WAIT_SEC):
        time.sleep(1)
        if DEVICE.exists() and KEYS.is_dir() and ORGKEY.exists():
            break
    if not (DEVICE.exists() and ORGKEY.exists()):
        say("  ! Enrollment did not finish within %d seconds.  Check %s." % (ENROLL_WAIT_SEC, ENROLL_LOG))
        return 1
    say("  Device enrollment complete.  The service started binding "
        "(the first binding takes a few minutes, depending on the existing logs).")

    say("")
    return move_root_key(a.key_out, ask=not a.key_out)


def _wipe(f: pathlib.Path) -> str:
    failed = ""
    try:
        n = f.stat().st_size
        with open(f, "r+b") as fh:
            fh.write(secrets.token_bytes(max(n, MIN_WIPE_BYTES)))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        failed = "%s: %s" % (type(exc).__name__, exc)
    f.unlink(missing_ok=True)
    return failed


def move_root_key(dest_dir: str | None, ask: bool = False) -> int:
    if not ORGKEY.exists():
        say("The device holds no root key copy.  "
            "The key was already moved, or enrollment has not happened yet.")
        return 0
    say("-" * RULE)
    say("  Moving the root key K0 off the device.  Until it moves, anyone who copies K0")
    say("  can recompute every tag.  Give a USB drive or an organization custody folder.")
    say("  The employee of this device must not be able to read that location.")
    if ask and not dest_dir:
        try:
            dest_dir = input("  Destination folder (leave empty to run "
                             "employee\\2_move_root_key.bat later): ").strip().strip('"')
        except EOFError:
            dest_dir = ""
    if not dest_dir:
        say("\n  ! The root key is still on the device (%s).  The lock keeps the employee out," % ORGKEY)
        say("    but anyone with administrator rights can read it.  "
            "Run employee\\2_move_root_key.bat as soon as possible.")
        return 0
    k0 = ORGKEY.read_text(encoding="utf-8").strip()
    enroll = json.loads((STORE / ENROLL_NAME).read_text(encoding="utf-8"))
    if core.key_commitment(bytes.fromhex(k0)) != enroll["key_commitment"]:
        raise SystemExit("The root key does not match the commitment in the enrollment certificate.  "
                         "Nothing was moved.")
    device = enroll.get("device_id", os.environ.get("COMPUTERNAME", "unknown"))
    dest = pathlib.Path(dest_dir) / ("SIDE_custody_%s_%s" % (device, util.now_stamp()))
    dest.mkdir(parents=True, exist_ok=False)
    (dest / core.K0_NAME).write_text(k0, encoding="utf-8")
    shutil.copy2(STORE / ENROLL_NAME, dest / ENROLL_NAME)
    shutil.copy2(SEAL_PUB, dest / SEAL_PUB_NAME)
    (dest / "00_README.txt").write_text(
        "SIDE organization custody copy for device %s\n\n"
        "k0.hex       Root key K0.  Only the organization keeps it.  "
        "It verifies collections (C1) and seal tags.\n"
        "enroll.json  Original enrollment certificate.  Compare it with the copy inside each collection.\n"
        "seal_pub.hex Seal public key given to this device.\n\n"
        "Do not keep this folder on the device.  Without it, C1 is impossible.\n" % device, encoding="utf-8")
    if (dest / core.K0_NAME).read_text(encoding="utf-8").strip() != k0:
        raise SystemExit("Could not read back the moved copy.  The device copy was not erased.")
    failed = _wipe(ORGKEY)
    say("\n  Root key moved: %s" % dest)
    if failed:
        say("  ! The device copy of the root key was deleted, "
            "but it could not be overwritten first (%s)." % failed)
    else:
        say("  The device copy of the root key was overwritten and deleted.")
    say("  The device now holds only the current stage key of each chain.")
    say("  * On an SSD the overwrite may not reach the original blocks.  Keep BitLocker on.")
    return 0


def status() -> int:
    banner("SIDE status")
    task = task_exists()
    n = service_count()
    say("  Scheduled task '%s' : %s" % (TASK, "registered" if task else "none"))
    say("  Service processes  : %d %s" % (n, "(normal)" if n == 1 else "(!)" if n > 1 else "(stopped)"))
    if INSTALL_RECORD.exists():
        s = json.loads(INSTALL_RECORD.read_text(encoding="utf-8"))
        say("  Install            : %s · employee %s · %s"
            % (s.get("installed_at_utc"), s.get("employee"), s.get("revision")))
    summary = ledger_summary()
    if summary:
        say("  Ledger             : %d records · last %s %s%s"
            % (summary["records"], summary["last"], summary["last_time"] or "",
               " · sealed (collected)" if summary["seal"] else ""))
        say("                       %s" % ", ".join("%s %d" % kv for kv in sorted(summary["kind"].items())))
    chains = list((STORE / core.CHAINS_DIR).glob("*.chain.json")) if STORE.exists() else []
    say("  Session chains     : %d" % max(0, len(chains) - (1 if DEVICE.exists() else 0)))
    say("  Root key copy      : %s" % ("still present (!) on the device.  Run employee\\2_move_root_key.bat."
                                       if ORGKEY.exists() else "not on the device"))
    if RESTART_LOG.exists():
        lines = RESTART_LOG.read_text(encoding="mbcs", errors="replace").splitlines()
        say("  Restarts           : %d (last: %s)" % (len(lines), lines[-1] if lines else "-"))
    return 0


def _service(*args) -> int:
    return util.run_service(BIN / SERVICE_NAME, *args, store=STORE, isolated=True)[0]


def bound_session_files() -> list[str]:
    found = set()
    for f in sorted((STORE / core.CHAINS_DIR).glob("*.chain.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for e in d.get("entries", []):
            sf = (e.get("record") or {}).get("session_file")
            if sf:
                found.add(sf)
    return sorted(found)


def collect(a) -> int:
    if not DEVICE.exists():
        say("Nothing to collect (no enrolled service folder: %s)." % STORE)
        return 1
    if ledger_summary().get("seal"):
        say("This service folder is already sealed.  "
            "Use the previous collection, or start anew with employee\\1_install.bat.")
        return 1
    banner("SIDE collect: stop the service, seal, and pack one archive")
    say("  After the seal, nothing more can be bound into this service folder.  To keep recording,")
    say("  run employee\\1_install.bat again after the collection "
        "(the previous service folder is moved aside, not deleted).")

    say("\n[1/5] Stopping the service (stop file)")
    normal = stop_service()
    say("    %s · scheduled task deleted" % ("normal stop" if normal else "forced stop"))

    say("\n[2/5] Sweeping once more, only the files already being bound")
    sweep_rc = _service("--once", "--source", "bound")
    if sweep_rc:
        say("    ! The final sweep ended with exit code %d.  "
            "Lines written since the last sweep may be unbound." % sweep_rc)
        say("      The manifest records the exit code (final_sweep_rc).  The collection continues.")

    say("\n[3/5] Sealing the chains and the device ledger (the organization adds the signature on receipt)")
    seal_rc = _service("--seal")
    if not ledger_summary().get("seal"):
        say("    ! Sealing failed (exit code %d).  "
            "The device ledger is not sealed, so nothing was collected." % seal_rc)
        say("      The service is stopped.  "
            "Run employee\\1_install.bat to continue binding in this service folder,")
        say("      or fix the cause shown above and run employee\\4_collect.bat again.")
        return 1
    if seal_rc:
        say("    ! Some chains could not be sealed (exit code %d).  "
            "The ledger records each one as seal_failed." % seal_rc)

    say("\n[4/5] Precollection check "
        "(the organization holds the root key, so it runs the tag recomputation C1)")
    passed = _service("--verify") == 0

    say("\n[5/5] Packing one archive")
    enroll = json.loads((STORE / ENROLL_NAME).read_text(encoding="utf-8"))
    device = enroll.get("device_id") or os.environ.get("COMPUTERNAME", "unknown")
    out_dir = pathlib.Path(a.out) if a.out else (HERE / "collections")
    out_dir.mkdir(parents=True, exist_ok=True)
    zp = out_dir / ("SIDE_collection_%s_%s.zip" % (device, util.now_stamp()))
    packed = []
    n_chain = n_sess = 0
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
        def pack(src: pathlib.Path, arc: str) -> None:
            zf.write(src, arc)
            packed.append({"path": arc, "bytes": src.stat().st_size, "sha256": util.sha256_file(src)})
        pub = store.find_seal_pub(STORE)
        for name in (ENROLL_NAME, SEAL_PUB_NAME, core.STATE_NAME):
            src = pub if name == SEAL_PUB_NAME else STORE / name
            if src is not None and src.exists():
                pack(src, name)
        for f in sorted((STORE / core.CHAINS_DIR).glob("*.json")):
            pack(f, core.CHAINS_DIR + "/" + f.name)
            n_chain += f.name.endswith(".chain.json")
        if a.include_logs:
            for sf in bound_session_files():
                sp = pathlib.Path(sf)
                if sp.exists():
                    pack(sp, core.SESSIONS_DIR + "/" + verify.source_key(sf))
                    n_sess += 1
        manifest = {"tool": "SIDE", "revision": REVISION_EXPECTED,
                    "collected_at_utc": utc_now(),
                    "device": device, "service_stop": "normal" if normal else "forced",
                    "final_sweep_rc": sweep_rc, "seal_rc": seal_rc,
                    "logs_included": bool(a.include_logs), "precollection_check_passed": passed,
                    "chain_files": n_chain, "session_log_files": n_sess, "files": packed,
                    "note": "The seal has no signature yet.  The verifier accepts it only after "
                            "the organization signs it with the seal private key.  "
                            "The organization runs the tag recomputation (C1) "
                            "with the root key K0 it keeps."}
        zf.writestr("00_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
        zf.writestr("00_README.txt",
                    "SIDE collection archive for device %s\n\n"
                    "The organization opens this zip with organization\\2_receive_collection.bat.\n"
                    "  1) Compare the files with the sha256 values in 00_manifest.json\n"
                    "  2) Compare enroll.json with the organization custody copy (SIDE_custody_*)\n"
                    "  3) Sign the seal with the seal private key\n"
                    "  4) Verify C1-C4 with the root key K0 and the seal public key\n"
                    "The key files (keys/) are not included.\n" % device)
    say("    %d chains%s" % (n_chain, " · %d session logs" % n_sess if a.include_logs else ""))
    say("\n" + "-" * RULE)
    say("  Created file: %s" % zp)
    say("  Send this file to the organization.  %s" % ("It contains the conversation text." if a.include_logs
                                                      else "It contains no conversation text."))
    say("-" * RULE)
    return 0


def uninstall() -> int:
    if not task_exists() and not service_count():
        say("No SIDE service is running.")
    else:
        normal = stop_service()
        say("Stopped the service and deleted the scheduled task (%s)."
            % ("normal stop" if normal else "forced stop"))
    say("The service folder (%s) was not deleted.  To collect it, run employee\\4_collect.bat." % STORE)
    if ORGKEY.exists():
        say("! The root key copy is still on the device: %s.  "
            "Move it with employee\\2_move_root_key.bat." % ORGKEY)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SIDE device administration (administrator rights)")
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("install")
    s.add_argument("--employee", help="employee account whose session logs are bound "
                                      "(default: the account signed in now)")
    s.add_argument("--key-out",
                   help="folder off the device that receives the root key right after enrollment")
    s.add_argument("--fresh", action="store_true",
                   help="move an unsealed previous service folder aside and enroll anew")
    s = sub.add_parser("root-key")
    s.add_argument("--key-out", help="folder off the device that receives the root key")
    sub.add_parser("status")
    s = sub.add_parser("collect")
    s.add_argument("--include-logs", action="store_true",
                   help="include the session logs (contains conversation text)")
    s.add_argument("--out", help="folder for the collection zip (default: collections\\ in this folder)")
    sub.add_parser("uninstall")
    a = ap.parse_args()
    util.keep_output_alive()
    if os.name != "nt":
        raise SystemExit("Runs on Windows only.")
    if not is_admin():
        raise SystemExit("Administrator rights are required.  "
                         "Open the terminal (or the bat file) with 'Run as administrator'.")
    if a.command == "install":
        return install(a)
    if a.command == "root-key":
        return move_root_key(a.key_out, ask=True)
    if a.command == "status":
        return status()
    if a.command == "collect":
        return collect(a)
    return uninstall()


if __name__ == "__main__":
    sys.exit(main())
