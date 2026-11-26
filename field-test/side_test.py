# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
# SPDX-License-Identifier: Apache-2.0
r"""SIDE field test on one PC: an administrator account (install, organization, verifier) and a
standard user account (employee).

  1_admin_install.bat              python side_test.py install   (administrator)
  2_employee_test.bat              python side_test.py employee  (employee, from C:\Users\Public\SIDE_test)
  3_admin_collect_and_verify.bat   python side_test.py collect   (administrator)
  9_admin_cleanup.bat              python side_test.py cleanup   (administrator)
  0_diagnose.bat                   python side_test.py diagnose  (administrator)

Every check is recorded as PASS, FAIL or INFO.  When stage 3 ends, the script writes
test_summary_<time>.txt into this folder.

Design notes:
- field-test\ sits next to employee\, organization\, verifier\ and src\. Install copies src\ next
  to the bundles because their bat files call ..\src\.
- The employee stage runs from a lone copy of this file in C:\Users\Public\SIDE_test, without
  src\. So the file keeps its own copies of a few side_core and side_util values (SIDs, RULE,
  STAMP, file names). The administrator stages load side_util from src\. load_util stops if the
  copies differ.
- The denyread session gets 3 lines before and 3 after SYSTEM is denied read. The service must
  still chain all 6 through its backup read.
- Windows commands print in the OEM code page (cp437 on English Windows), not UTF-8.
- The console is switched to UTF-8 so that symbols such as '·' and '→' print. Windows Terminal
  (WT_SESSION) already uses UTF-8.
- While the service runs, the last service_start in the ledger has no stop. The verifier cannot
  tell running from dead and reports it. In verify_live that signal alone is expected.
- The ledger (_device) is judged apart from the session chains. The attack and the reboot test
  leave observations and broken intervals there, so "no signals" would be a false FAIL. Instead
  a broken interval must be explained by a boot record in the Windows System log, and an
  observation by an attack file of this run or a cursor restore right after a reboot.
- If the employee test ran after a reboot but before the service came back, the service saw none
  of it, and the line, tamper and delete verdicts all fail. Stage 3 checks for this one cause.
- service_start can come minutes after boot. The service.log start lines tell a late scheduled
  task (a late "watch.cmd start") from a late Python (an early "watch.cmd start").
- An edit or delete between session_seen and session_open stays hidden, so stage 3 records that
  delay.
- The seal signature covers only seal.body. seal.tag is an HMAC that needs the device key, so a
  package with only seal.tag changed passes by design. That check is INFO.
- The service records session_seen before it reads a file. In the diagnosis file the last file
  seen marks where a stalled service stopped. The diagnosis file holds no conversation text.
- Cleanup also removes side-test, where the manual walkthrough puts first.jsonl. The next test
  would bind a leftover copy. icacls /reset first clears the denyread deny entry.
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
DRIVE = pathlib.Path(os.environ.get("SystemDrive", "C:") + "\\")
INST = DRIVE / "SIDE_install"
ORGD = DRIVE / "SIDE_org_side"
PUB = pathlib.Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "SIDE_test"
PD = pathlib.Path(os.environ.get("ProgramData", r"C:\ProgramData"))
BASE = PD / "SIDE"
DEV = INST / "employee"
ORG = ORGD / "organization"
VIEW = ORGD / "verifier"
DEV_SRC = INST / "src"
ORG_SRC = ORGD / "src"
STATE = ORGD / "test_state.json"
R1 = ORGD / "test_result_1_install.json"
PUBINFO = PUB / "test_info.json"
EMP = PUB / "employee_result.json"
SERVICE = BASE / "bin" / "side_service.py"
TASK = "SIDE"
SID_SYSTEM, SID_USERS = "S-1-5-18", "S-1-5-32-545"
RULE = 62
STAMP = "%Y%m%d_%H%M%S"
CORE_NAMES = {"LEDGER_NAME": "_device.chain.json", "CHAINS_DIR": "chains", "K0_NAME": "k0.hex",
              "ENROLL_NAME": "enroll.json", "SEAL_PUB_NAME": "seal_pub.hex",
              "SEAL_SECRET_NAME": "seal_secret.hex"}
LEDGER_NAME, CHAINS_DIR, K0_NAME = CORE_NAMES["LEDGER_NAME"], CORE_NAMES["CHAINS_DIR"], CORE_NAMES["K0_NAME"]
ENROLL_NAME, SEAL_PUB_NAME = CORE_NAMES["ENROLL_NAME"], CORE_NAMES["SEAL_PUB_NAME"]
SEAL_SECRET_NAME = CORE_NAMES["SEAL_SECRET_NAME"]
PY = sys.executable
NORMAL_LINES = 20
DENYREAD_LINES = 6

results: list[dict] = []
LOG: pathlib.Path | None = None
util = None


def load_util() -> None:
    global util
    sys.path.insert(0, str(REPO / "src"))
    import side_core
    import side_util
    util = side_util
    stale = [k for k, v in CORE_NAMES.items() if getattr(side_core, k) != v]
    stale += [k for k, v in (("RULE", RULE), ("STAMP", STAMP)) if getattr(side_util, k) != v]
    if stale:
        raise SystemExit("side_test.py copies of %s differ from src\\.  Update side_test.py."
                         % ", ".join(stale))


def say(s: str = "") -> None:
    try:
        print(s, flush=True)
    except UnicodeEncodeError:
        print(s.encode("ascii", errors="replace").decode("ascii"), flush=True)
    if LOG:
        try:
            with LOG.open("a", encoding="utf-8") as fh:
                fh.write(s + "\n")
        except OSError:
            pass


def writable_dir() -> pathlib.Path:
    for d in (HERE, pathlib.Path(os.environ.get("USERPROFILE", "")) / "Desktop",
              pathlib.Path(os.environ.get("TEMP", "."))):
        try:
            t = d / ".side_test_w"
            t.write_text("x", encoding="utf-8")
            t.unlink()
            return d
        except OSError:
            continue
    return pathlib.Path(".")


def heading(s: str) -> None:
    say("")
    say("=" * RULE)
    say("  " + s)
    say("=" * RULE)


def check(stage: str, name: str, ok, detail: str = "") -> None:
    results.append({"stage": stage, "items": name, "ok": ok, "detail": detail})
    mark = {True: "PASS", False: "FAIL", None: "INFO"}[ok]
    say("  [%s] %s%s" % (mark, name, ("  -- " + detail) if detail else ""))


def run(args, cwd=None, env=None, show=True) -> tuple[int, str]:
    e = dict(os.environ, PYTHONIOENCODING="utf-8")
    e.update(env or {})
    p = subprocess.Popen([str(a) for a in args], cwd=str(cwd) if cwd else None, env=e,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         text=True, encoding="utf-8", errors="replace")
    out = []
    for line in p.stdout:
        line = line.rstrip("\r\n")
        out.append(line)
        if show:
            say("    | " + line)
    p.wait()
    return p.returncode, "\n".join(out)


def _oem() -> str:
    try:
        import ctypes
        return "cp%d" % ctypes.windll.kernel32.GetOEMCP()
    except Exception:
        return "cp437"


OEM = _oem() if os.name == "nt" else "utf-8"


def sysrun(args) -> tuple[int, str]:
    r = subprocess.run([str(a) for a in args], capture_output=True, stdin=subprocess.DEVNULL)
    out = (r.stdout or b"") + (r.stderr or b"")
    return r.returncode, out.decode(OEM, errors="replace").strip()


def console_utf8() -> str:
    if os.name != "nt" or os.environ.get("WT_SESSION"):
        return "skipped"
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleOutputCP(65001)
        k32.SetConsoleCP(65001)
        return "UTF-8"
    except Exception as e:
        return "failed %s" % e


def ps(script: str) -> str:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script],
                       capture_output=True, stdin=subprocess.DEVNULL)
    return (r.stdout or b"").decode("utf-8", errors="replace").strip()


def is_admin() -> bool:
    return subprocess.run(["net", "session"], capture_output=True).returncode == 0


def task_exists() -> bool:
    return sysrun(["schtasks", "/Query", "/TN", TASK])[0] == 0


def wait(seconds: int, why: str) -> None:
    say("  %s -- waiting %d s" % (why, seconds))
    time.sleep(seconds)


def save(p: pathlib.Path, d) -> None:
    p.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def load(p: pathlib.Path):
    return json.loads(p.read_text(encoding="utf-8"))


def ask(question: str, default: str = "") -> str:
    try:
        v = input(question).strip()
    except EOFError:
        v = ""
    return v or default


def chain_blocks(out: str) -> dict:
    res: dict = {}
    cur = None
    for raw in out.splitlines():
        s = raw.strip().lstrip("|").strip()
        m = re.match(r"^(OK|FAIL)\s+(\S+\.chain\.json)\s+records\s+(\d+)(?:\s+·\s+lines\s+(\d+))?(.*)$", s)
        if m:
            cur = m.group(2)
            res[cur] = {"ok": m.group(1) == "OK", "records": int(m.group(3)),
                        "lines": int(m.group(4) or 0), "signals": [], "extra": [m.group(5).strip()]}
            continue
        if not s:
            cur = None
            continue
        if cur and s.startswith("- "):
            res[cur]["signals"].append(s[2:])
        elif cur and (s.startswith("·") or s.lower().startswith("service interval")):
            res[cur]["extra"].append(s)
    return res


def find_block(blocks: dict, kind: str, tag: str):
    for k, v in blocks.items():
        if k.startswith("%s_%s_" % (kind, tag)):
            return k, v
    return None, None


def judge_chains(stage: str, blocks: dict, tag: str, ledger) -> None:
    _, n = find_block(blocks, "normal", tag)
    check(stage, "normal session: no signals · %d lines" % NORMAL_LINES,
          bool(n and n["ok"] and n["lines"] == NORMAL_LINES),
          "missing" if not n else "%d lines · signals %s" % (n["lines"], n["signals"] or "none"))
    _, t = find_block(blocks, "tamper", tag)
    check(stage, "edited session tamper: shows as content mismatch",
          bool(t and not t["ok"] and any("content mismatch" in f for f in t["signals"])),
          "missing" if not t else "; ".join(t["signals"]) or "no signals")
    _, d = find_block(blocks, "delete", tag)
    check(stage, "deleted session delete: shows as source absent",
          bool(d and not d["ok"] and any("source absent" in f for f in d["signals"])),
          "missing" if not d else "; ".join(d["signals"]) or "no signals")
    _, r = find_block(blocks, "denyread", tag)
    check(stage, "session denyread with denied read: no signals · %d lines" % DENYREAD_LINES,
          bool(r and r["ok"] and r["lines"] == DENYREAD_LINES),
          "missing" if not r else "%d lines · signals %s" % (r["lines"], r["signals"] or "none"))
    others = [k for k, v in blocks.items() if not v["ok"] and k != LEDGER_NAME
              and not k.startswith(("tamper_%s_" % tag, "delete_%s_" % tag))]
    check(stage, "other session chains have no signals", not others, ", ".join(others))
    dev = blocks.get(LEDGER_NAME)
    if dev:
        check(stage, "ledger", None, " / ".join(x for x in dev["extra"] if x))
        check(stage, "ledger: no service interval read without the backup privilege",
              not any("without the backup privilege" in x for x in dev["extra"]))
    judge_ledger(stage, dev, ledger, tag)


_power_meaning = {6005: "boot (event log started)", 6006: "normal shutdown", 6008: "unexpected shutdown",
                  1074: "shutdown or restart request", 41: "power loss (Kernel-Power 41)",
                  42: "entering sleep",
                  107: "resume from sleep", 12: "boot (OS start)", 13: "OS shutdown"}
_power_cache: dict = {}


def _utc(s):
    try:
        t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.astimezone()
    return t.astimezone(datetime.timezone.utc)


def _clock(t) -> str:
    return t.astimezone().strftime("%m-%d %H:%M:%S") if t else "?"


def power_events(start, end) -> list:
    k = (start, end)
    if k in _power_cache:
        return _power_cache[k]
    f = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    out = ps("$s=[datetime]::Parse('%s'); $e=[datetime]::Parse('%s'); "
             "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$s; EndTime=$e; "
             "Id=6005,6006,6008,1074,41,42,107,12,13} -ErrorAction SilentlyContinue | "
             "ForEach-Object { $_.TimeCreated.ToUniversalTime().ToString('o') + '|' + $_.Id + '|' "
             "+ $_.ProviderName }"
             % (f(start - datetime.timedelta(seconds=60)), f(end + datetime.timedelta(seconds=60))))
    res = []
    for l in out.splitlines():
        p = l.strip().split("|")
        if len(p) != 3 or not p[1].isdigit():
            continue
        i, prov = int(p[1]), p[2]
        if i in (12, 13) and "Kernel-General" not in prov:
            continue
        if i in (41, 42, 107) and "Kernel-Power" not in prov:
            continue
        res.append((_utc(p[0]), _power_meaning.get(i, str(i)), i == 6005 or i == 12))
    res.sort(key=lambda x: x[0] or start)
    _power_cache[k] = res
    return res


def judge_ledger(stage: str, dev, ledger, tag: str) -> None:
    if ledger is None:
        check(stage, "read the ledger file", False,
              "The ledger could not be read, so broken intervals and observations cannot be explained")
        return
    recs = [e.get("record") or {} for e in ledger.get("entries", [])]
    starts = [i for i, r in enumerate(recs) if r.get("kind") == "service_start"]

    after_reboot: set = set()
    broken = 0
    for a, b in zip(starts, starts[1:]):
        if any(r.get("kind") == "service_stop" for r in recs[a + 1:b]):
            continue
        broken += 1
        last = max((t for t in (_utc(r.get("ts_recorded")) for r in recs[a:b]) if t), default=None)
        t1 = _utc(recs[b].get("ts_recorded"))
        events = power_events(last, t1) if last and t1 else []
        boots = [x for x in events if x[2]]
        text = "last record of interval seq %s at %s → restart seq %s at %s · System log in between: %s" % (
            recs[a].get("seq"), _clock(last), recs[b].get("seq"), _clock(t1),
            ", ".join("%s %s" % (_clock(t), meaning) for t, meaning, _ in events) or "no power events")
        if boots:
            after_reboot.add(b)
        check(stage, "ledger: interval broken without a stop → service came back after a reboot "
                     "(optional reboot test)",
              bool(boots),
              text + ("" if boots else " -- if this was not a reboot, find out why the service ended"
                                       " without a stop record"))
    if not broken:
        check(stage, "ledger: no interval broken without a stop (correct if the reboot test was skipped)",
              None, "0")

    attack = ("tamper_%s_" % tag, "delete_%s_" % tag)
    explained, unexplained = [], []
    for i, r in enumerate(recs):
        if r.get("kind") != "observation":
            continue
        name = os.path.basename(str(r.get("session_file") or r.get("chain") or ""))
        prev_start = max((s for s in starts if s < i), default=None)
        text = "seq %s %s %s" % (r.get("seq"), r.get("what"), name)
        if name.startswith(attack):
            explained.append(text + " (attack file)")
        elif (r.get("what") in ("cursor_restored_from_chain", "state_unreadable")
              and prev_start in after_reboot):
            explained.append(text + " (right after a reboot)")
        else:
            unexplained.append(text)
    if explained or unexplained:
        check(stage, "ledger: all %d observations are explained by attack files or a reboot"
              % (len(explained) + len(unexplained)),
              not unexplained, "; ".join(["unexplained: " + x for x in unexplained] + explained))

    known = ("has no matching service_stop", "is still open", "observation at seq", "no service_stop yet")
    other = [f for f in (dev["signals"] if dev else []) if not any(x in f for x in known)]
    check(stage, "ledger: no other signals", not other, "; ".join(other))


def service_lines() -> list[str]:
    out = ps("Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
             "Where-Object { $_.CommandLine -like '*side_service*--watch*' } | "
             "ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User + '|' "
             "+ $_.CommandLine }")
    return [l for l in out.splitlines() if "|" in l]


def restart_count() -> int:
    f = BASE / "restart.log"
    if not f.exists():
        return 0
    return len([l for l in f.read_text(encoding="mbcs", errors="replace").splitlines() if l.strip()])


def check_deployment(stage: str) -> None:
    install = load(BASE / "install.json")
    lines = service_lines()
    check(stage, "one service process", len(lines) == 1, "%d" % len(lines))
    if lines:
        user, cmd = lines[0].split("|", 1)
        check(stage, "service runs as SYSTEM", user.strip().upper() == "SYSTEM", user.strip())
        check(stage, "command line has --read-mode backup", "--read-mode backup" in cmd)
        check(stage, "command line has the employee session log path",
              install["pattern"][0].lower() in cmd.lower(), install["pattern"][0])
    t = ps("$t = Get-ScheduledTask -TaskName SIDE; $s = $t.Settings; "
           "'{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $t.Principal.UserId, $t.Triggers[0].CimClass.CimClassName, "
           "$s.DisallowStartIfOnBatteries, $s.StopIfGoingOnBatteries, $s.ExecutionTimeLimit, "
           "$t.State, $s.Priority").split("|")
    if len(t) == 7:
        check(stage, "scheduled task: SYSTEM",
              t[0].upper() in ("SYSTEM", "S-1-5-18", "NT AUTHORITY\\SYSTEM"), t[0])
        check(stage, "scheduled task: runs at system startup", t[1] == "MSFT_TaskBootTrigger", t[1])
        check(stage, "scheduled task: starts and keeps running on battery",
              t[2] == "False" and t[3] == "False",
              "%s/%s" % (t[2], t[3]))
        check(stage, "scheduled task: no run time limit", t[4] == "PT0S", t[4])
        check(stage, "scheduled task: running", t[5] == "Running", t[5])
        check(stage, "scheduled task: normal priority (4)", t[6].strip() == "4", t[6].strip())
    else:
        check(stage, "read the scheduled task", False, "|".join(t))
    try:
        wc = (BASE / "bin" / "watch.cmd").read_bytes().decode("mbcs", errors="replace")
        check(stage, "watch.cmd writes service.log", "service.log" in wc)
    except OSError as e:
        check(stage, "watch.cmd writes service.log", False, str(e))
    dirs = [BASE, BASE / "store", BASE / "org", BASE / "bin"]
    out = ps("; ".join(
        "$ids = (Get-Acl -LiteralPath '%s').Access | ForEach-Object { try { $_.IdentityReference."
        "Translate([Security.Principal.SecurityIdentifier]).Value } catch { $_.IdentityReference.Value } } "
        "| Sort-Object -Unique; '%s|' + ($ids -join ',')" % (d, d.name) for d in dirs))
    for l in out.splitlines():
        name, ids = l.split("|", 1)
        extra = [x for x in ids.split(",") if x and x not in (util.SID_SYSTEM, util.SID_ADMINS)]
        check(stage, "folder permissions %s: SYSTEM and Administrators only" % name,
              not extra, ", ".join(extra))
    who = (BASE / "whoami.txt").read_bytes().decode(OEM, errors="replace").lower()
    check(stage, "whoami.txt = nt authority\\system", "nt authority\\system" in who)
    k0 = [str(p) for p in BASE.rglob("*") if "k0" in p.name.lower()]
    check(stage, "no copy of the root key on the device", not k0, ", ".join(k0))


def verify_live(stage: str) -> None:
    env = {"SIDE_STORE": str(BASE / "store")}
    def only_running(b: dict) -> bool:
        bad = {k: v for k, v in b.items() if not v["ok"]}
        dv = bad.get(LEDGER_NAME)
        return (set(bad) == {LEDGER_NAME} and bool(dv["signals"]) and all(
            "no service_stop yet" in f or re.search(r"service_start at seq \d+ is still open", f)
            for f in dv["signals"]))

    rc, out = run([PY, SERVICE, "--verify"], env=env, show=False)
    b = chain_blocks(out)
    if rc and not only_running(b):
        time.sleep(5)
        rc, out = run([PY, SERVICE, "--verify"], env=env, show=False)
        b = chain_blocks(out)
    ok = rc == 0 or only_running(b)
    check(stage, "verify the chains bound so far "
                 "(without the root key · an open interval while running is normal)", ok,
          "%d chains%s" % (len(b), " · the last start in the ledger is open (running)" if ok and rc else
                           "" if ok else " · " + "; ".join(
                               "%s: %s" % (k, v["signals"]) for k, v in b.items() if not v["ok"])))
    check(stage, "no service interval read without the backup privilege",
          "without the backup privilege" not in out)


def find_bundle(name: str) -> pathlib.Path:
    d = REPO / name
    if d.is_dir():
        return d
    raise SystemExit("Folder %s not found.  Run this test from a full copy of the repository." % d)


def pick_employee() -> str:
    out = ps("$adm = @(Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | "
             "ForEach-Object { $_.SID.Value }); "
             "$prof = @(Get-CimInstance Win32_UserProfile | ForEach-Object { $_.SID }); "
             "Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { '{0}|{1}|{2}' -f "
             "$_.Name, ($adm -contains $_.SID.Value), ($prof -contains $_.SID.Value) }")
    candidates, admins = [], []
    for l in out.splitlines():
        p = l.split("|")
        if len(p) == 3:
            (admins if p[1] == "True" else candidates if p[2] == "True" else []).append(p[0])
    me = os.environ.get("USERNAME", "")
    candidates = [x for x in candidates if x.lower() != me.lower()]
    say("  Standard user accounts on this PC (logged in at least once):")
    for i, x in enumerate(candidates, 1):
        say("    [%d] %s" % (i, x))
    if not candidates:
        say("    (none) -- Create a standard user account, log in to it once and run this again, "
            "or type the name.")
    answer = ask("  Employee account number or name%s: " % (" (Enter = 1)" if candidates else ""),
                 "1" if candidates else "")
    if answer.isdigit() and candidates and 1 <= int(answer) <= len(candidates):
        return candidates[int(answer) - 1]
    if not answer:
        raise SystemExit("No employee account was chosen.")
    if answer in admins:
        raise SystemExit("'%s' is an administrator account.  The employee must be a standard user "
                         "for the test to mean anything." % answer)
    return answer


def lock_down(d: pathlib.Path, mysid: str) -> None:
    r = util.lock_folder(d, mysid)
    if r.returncode:
        raise SystemExit("Could not lock the folder: %s\n%s" % (d, (r.stdout or "") + (r.stderr or "")))


def install() -> int:
    stage = "1 install"
    heading("SIDE field test 1/3 -- administrator: install and check the deployment")
    if not is_admin():
        raise SystemExit("Administrator rights are required.")
    if BASE.exists() or task_exists() or INST.exists() or ORGD.exists() or PUB.exists():
        say("  A previous attempt is still present (%s, %s, %s, %s or scheduled task SIDE)."
            % (BASE, INST, ORGD, PUB))
        if ask("  Delete it and start over? (Y/n): ", "y").lower() != "y":
            return 1
        cleanup_run()
        if BASE.exists() or task_exists() or INST.exists() or ORGD.exists():
            raise SystemExit("The previous attempt could not be fully removed.  "
                             "Restart the PC and run this bat file again.")
    bundles = {k: find_bundle(k) for k in ("employee", "organization", "verifier", "src")}
    say("  Python : %s" % PY)
    if str(PY).lower().startswith(str(pathlib.Path(os.environ.get("SystemDrive", "C:") + "\\Users")).lower()):
        raise SystemExit("This Python is in a user folder.  Run the test with a Python for all users.")
    employee = pick_employee()
    say("  Employee account: %s" % employee)
    mysid = sysrun(["whoami", "/user", "/fo", "csv", "/nh"])[1].split(",")[-1].strip().strip('"')

    heading("[1] Create the folders, lock them against the employee, copy the bundles and src")
    for d in (INST, ORGD):
        d.mkdir(parents=True)
        lock_down(d, mysid)
    for k, dst in (("employee", DEV), ("organization", ORG), ("verifier", VIEW),
                   ("src", DEV_SRC), ("src", ORG_SRC)):
        shutil.copytree(bundles[k], dst, ignore=shutil.ignore_patterns("__pycache__"))
        say("    %s → %s" % (bundles[k], dst))
    check(stage, "copy the bundles and src",
          all(p.exists() for p in (DEV_SRC / "side_device.py", ORG_SRC / "side_org.py",
                                   ORG_SRC / "viewer.py")))

    heading("[2] Organization: make the seal key pair and put only the public key in the device bundle")
    rc, _ = run([PY, ORG_SRC / "side_org.py", "seal-key"], cwd=ORG)
    check(stage, "organization seal key pair", rc == 0 and (ORG / "org_keys" / SEAL_SECRET_NAME).exists())
    shutil.copy2(ORG / SEAL_PUB_NAME, DEV / SEAL_PUB_NAME)
    check(stage, "no private key in the device bundle", not list(DEV.rglob("seal_secret*")))

    heading("[3] Install -- register the SYSTEM scheduled task, enroll, "
            "move the root key to the organization side")
    rc, out = run([PY, DEV_SRC / "side_device.py", "install", "--employee", employee, "--key-out", ORGD],
                  cwd=DEV)
    ok = rc == 0 and "enrollment complete" in out and "moved" in out
    check(stage, "install · enroll · move the root key", ok, "" if ok else "rc=%d" % rc)
    custody = sorted(ORGD.glob("SIDE_custody_*"))
    if not ok or not custody:
        save(R1, results)
        raise SystemExit("The install did not finish (rc=%d).  The enrollment and service records go into "
                         "the diagnosis file.\n"
                         "Restart the PC and run this bat file again.  "
                         "It removes what is left and starts over." % rc)
    check(stage, "organization custody copy (k0 · enroll · seal_pub)",
          all((custody[-1] / f).exists() for f in (K0_NAME, ENROLL_NAME, SEAL_PUB_NAME)), str(custody[-1]))
    save(STATE, {"employee": employee, "custody": str(custody[-1]),
                 "installed_at": datetime.datetime.now().isoformat(timespec="seconds"),
                 "pattern": load(BASE / "install.json")["pattern"]})

    heading("[4] Check the deployment")
    wait(10, "letting the service do its first sweep")
    check_deployment(stage)
    verify_live(stage)

    heading("[5] Put the employee test files in %s" % PUB)
    PUB.mkdir(parents=True, exist_ok=True)
    sysrun(["icacls", PUB, "/grant", "*%s:(OI)(CI)M" % SID_USERS])
    for f in (EMP, EMP.with_suffix(".txt")):
        f.unlink(missing_ok=True)
    shutil.copy2(HERE / "side_test.py", PUB / "side_test.py")
    shutil.copy2(HERE / "2_employee_test.bat", PUB / "2_employee_test.bat")
    save(PUBINFO, {"employee": employee})
    check(stage, "place the employee test files", (PUB / "2_employee_test.bat").exists(), str(PUB))

    save(R1, results)
    failed = sum(1 for r in results if r["ok"] is False)
    heading("1/3 done -- %d FAIL" % failed)
    say("  Next steps:")
    say("   (optional) Reboot test: restart the PC now and log in with the administrator account.")
    say("          Stage 3 reads the ledger to check that the service came back on its own.")
    say("   1) Switch to the employee account '%s' (Win+L → Other user, or sign out)." % employee)
    say("   2) In the Explorer address bar open  %s  → double click 2_employee_test.bat." % PUB)
    say("   3) When it ends, return to the administrator account and run 3_admin_collect_and_verify.bat.")
    return 0


def _attempt(name: str, fn) -> None:
    try:
        fn()
        check("2 employee", name, False, "it succeeded")
    except FileNotFoundError as e:
        check("2 employee", name, None, "file not found: %s" % e)
    except OSError as e:
        check("2 employee", name, True, "denied (%s)" % e.__class__.__name__)


def _command(name: str, args) -> None:
    rc, out = sysrun(args)
    check("2 employee", name, rc != 0, out.splitlines()[0][:90] if out else "rc=%d" % rc)


def employee() -> int:
    stage = "2 employee"
    heading("SIDE field test 2/3 -- employee: normal work, attempts to stop the service, editing own logs")
    if is_admin():
        say("This window has administrator rights.  Run this stage from the employee account "
            "by a double click (without administrator rights).")
        return 1
    me = os.environ.get("USERNAME", "")
    expected = load(PUBINFO)["employee"] if PUBINFO.exists() else ""
    if expected and me.lower() != expected.split("\\")[-1].lower():
        say("  The current account is '%s', but the install bound '%s'." % (me, expected))
        if ask("  Continue anyway? (y/N): ").lower() != "y":
            return 1
    tag = datetime.datetime.now().strftime("%m%d%H%M%S")
    d = pathlib.Path(os.environ["USERPROFILE"]) / ".claude" / "projects" / ("side-test-" + tag)
    d.mkdir(parents=True, exist_ok=True)
    f = {k: d / ("%s_%s.jsonl" % (k, tag)) for k in ("normal", "tamper", "delete", "denyread")}

    def add(k: str, n: int) -> None:
        t = datetime.datetime.now().astimezone().isoformat()
        with open(f[k], "ab") as fh:
            fh.write(('{"type":"user","n":%d,"t":"%s"}\n' % (n, t)).encode("ascii"))

    heading("[1] Write session logs (same place as Claude Code: %s)" % d)
    for n in range(1, NORMAL_LINES + 1):
        add("normal", n)
        time.sleep(0.3)
    for n in range(1, 11):
        add("tamper", n)
    for n in range(1, 6):
        add("delete", n)
    for n in range(1, DENYREAD_LINES // 2 + 1):
        add("denyread", n)
    wait(60, "letting the service bind them (right after a boot, one new file took up to 10 s in field runs)")

    heading("[2] Touch own logs -- this cannot be prevented, but collection must reveal it")
    with open(f["tamper"], "r+b") as fh:
        fh.seek(19)
        original = fh.read(1)
        fh.seek(19)
        fh.write(b"9")
    check(stage, "tamper: change one character of the first chained line (same size)", original == b"1",
          "%r → b'9'" % original)
    f["delete"].unlink()
    check(stage, "delete: delete a chained file", not f["delete"].exists())
    rc, out = sysrun(["icacls", f["denyread"], "/deny", "*%s:(R)" % SID_SYSTEM])
    check(stage, "denyread: deny read to SYSTEM (icacls /deny)", rc == 0, out.splitlines()[-1] if out else "")
    for n in range(DENYREAD_LINES // 2 + 1, DENYREAD_LINES + 1):
        add("denyread", n)
    wait(30, "checking that the service keeps binding the denied file")

    heading("[3] Attempts to stop or open the service -- every one must be denied")
    _command("end the scheduled task (schtasks /End)", ["schtasks", "/End", "/TN", TASK])
    _command("delete the scheduled task (schtasks /Delete)", ["schtasks", "/Delete", "/TN", TASK, "/F"])
    k = ps("Get-Process python,pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne %d } | "
           "ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; 'killed' } "
           "catch { 'denied' } }" % os.getpid())
    denied, killed = k.count("denied"), k.count("killed")
    check(stage, "kill the service process (Stop-Process)", True if denied and not killed else None,
          "denied %d · ended %d (ended ones are the employee's own python -- stage 3 checks "
          "that the service is alive)" % (denied, killed))
    _attempt("open the service folder", lambda: os.listdir(BASE))
    _attempt("write the stop file (org\\STOP)", lambda: open(BASE / "org" / "STOP", "w").close())
    _attempt("delete the ledger", lambda: os.remove(BASE / "store" / CHAINS_DIR / LEDGER_NAME))
    _attempt("open the key folder", lambda: os.listdir(BASE / "store" / "keys"))
    _attempt("change the service code (bin\\watch.cmd)",
             lambda: open(BASE / "bin" / "watch.cmd", "a").close())
    _command("take ownership of the service folder (takeown)", ["takeown", "/F", BASE])
    _command("change service folder permissions (icacls /grant)", ["icacls", BASE, "/grant", "%s:F" % me])
    _attempt("read the organization seal private key",
             lambda: open(ORG / "org_keys" / SEAL_SECRET_NAME).read())
    _attempt("open the organization side folder (root key custody)", lambda: os.listdir(ORGD))
    _attempt("open the install folder", lambda: os.listdir(INST))

    save(EMP, {"employee": me, "tag": tag, "folder": str(d), "result": results})
    EMP.with_suffix(".txt").write_text(report(results), encoding="utf-8")
    failed = sum(1 for r in results if r["ok"] is False)
    heading("2/3 done -- %d FAIL" % failed)
    say("  Next: close this window, sign out (or Win+L) and run 3_admin_collect_and_verify.bat "
        "from the administrator account.")
    return 0


def line_count(chain: pathlib.Path) -> int:
    d = load(chain)
    return sum(1 for e in d.get("entries", []) if (e.get("record") or {}).get("kind") == "line")


def is_sealed(status_text: str) -> bool:
    return bool(re.search(r"\bsealed\b", status_text))


def collect() -> int:
    stage = "3 collect"
    heading("SIDE field test 3/3 -- administrator: collection, organization receive, disclosure, verifier")
    if not is_admin():
        raise SystemExit("Administrator rights are required.")
    if not STATE.exists():
        say("Run 1_admin_install first.")
        return 1
    if not EMP.exists():
        say("No employee test result (%s).  Run 2_employee_test.bat from the employee account first." % EMP)
        return 1
    st, emp = load(STATE), load(EMP)
    tag = emp["tag"]

    heading("[1] Service state after the employee attacks")
    if is_sealed(status_text()):
        check(stage, "already collected, so the service checks follow the previous attempt's records", None)
        return collect_continue(stage, st, tag)
    lines = service_lines()
    check(stage, "still one service process (SYSTEM)",
          len(lines) == 1 and lines[0].split("|")[0].upper() == "SYSTEM",
          "%d" % len(lines))
    n = restart_count()
    check(stage, "no automatic restart (the employee could not kill it)", n == 0, "restart.log %d lines" % n)
    try:
        employee_time = datetime.datetime.strptime("%d%s" % (datetime.date.today().year, tag),
                                                   "%Y%m%d%H%M%S").astimezone()
        ent = load(BASE / "store" / CHAINS_DIR / LEDGER_NAME).get("entries", [])
        starts = [_utc((e.get("record") or {}).get("ts_recorded")) for e in ent
                  if (e.get("record") or {}).get("kind") == "service_start"]
        starts = [t for t in starts if t]
        if not starts:
            check(stage, "service was already running during the employee test", False,
                  "the ledger has no service_start yet")
        else:
            earlier = [t for t in starts if t <= employee_time]
            check(stage, "service was already running during the employee test (service_start before it)",
                  bool(earlier) and starts[-1] <= employee_time,
                  "employee start %s · last service start %s%s" % (
                      _clock(employee_time), _clock(starts[-1]),
                      "" if starts[-1] <= employee_time else
                      " -- the service came up only after the employee test.  The chained line, tamper"
                      " and delete FAILs below all come from this one cause.  After a reboot,"
                      " run 0_diagnose.bat as administrator"
                      " and confirm that the last service_start in the ledger is later than the reboot"
                      " before you run the employee test"))
    except Exception as e:
        check(stage, "service was already running during the employee test", None, "no verdict %s" % e)
    try:
        text = (BASE / "service.log").read_bytes().decode("utf-8", errors="replace")
        start_lines = [x.strip() for x in text.splitlines()
                       if x.strip().endswith("watch.cmd start") or "python start" in x]
        boot = ps("(Get-CimInstance Win32_OperatingSystem)"
                  ".LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')").strip()
        check(stage, "service.log start records (to locate a delay after boot)", None,
              "last boot %s · %s" % (boot, " | ".join(start_lines[-6:]) or "no start lines"))
    except Exception as e:
        check(stage, "service.log start records (to locate a delay after boot)", None,
              "could not read %s" % e)
    try:
        seen = {}
        delays = []
        for e in ent:
            r = e.get("record") or {}
            sf = pathlib.Path(r.get("session_file") or "").name
            if tag not in sf:
                continue
            t = _utc(r.get("ts_recorded"))
            if r.get("kind") == "session_seen":
                seen[sf] = t
            elif r.get("kind") in ("session_open", "sweep_error") and sf in seen and t:
                delays.append("%s %s %.1f s" % (sf.split("_")[0],
                                                "open" if r.get("kind") == "session_open" else "error",
                                                (t - seen[sf]).total_seconds()))
        first = min(seen.values()) if seen else None
        check(stage, "time until the service saw the employee files and started binding", None,
              ("first seen %.1f s after the employee start · " % (first - employee_time).total_seconds()
               if first else "not seen · ")
              + (" · ".join(delays) or "-"))
    except Exception as e:
        check(stage, "time until the service saw the employee files and started binding", None,
              "no verdict %s" % e)
    chains = BASE / "store" / CHAINS_DIR
    for kind, expected in (("normal", NORMAL_LINES), ("denyread", DENYREAD_LINES)):
        c = sorted(chains.glob("%s_%s_*.chain.json" % (kind, tag))) if chains.exists() else []
        try:
            k = line_count(c[0]) if c else -1
        except (OSError, ValueError):
            k = -1
        what = "normal session" if kind == "normal" else "session denyread with denied read (backup read)"
        check(stage, "before collection, lines the service chained: %s = %d" % (what, expected),
              k == expected,
              "%d lines" % k if c else "no chain")
    return collect_continue(stage, st, tag)


def collect_continue(stage: str, st: dict, tag: str) -> int:
    heading("[2] Collection (with session logs) -- stop the service with the stop file, seal, zip")
    out_dir = DEV / "collections"
    old_zips = sorted(out_dir.glob("SIDE_collection_*.zip")) if out_dir.exists() else []
    if old_zips and is_sealed(status_text()):
        say("  A collection already exists -- continuing with it: %s" % old_zips[-1].name)
        zp = old_zips[-1]
        check(stage, "collection (uses the previous attempt's zip)", None, str(zp))
    else:
        rc, out = run([PY, DEV_SRC / "side_device.py", "collect", "--include-logs"], cwd=DEV)
        check(stage, "normal stop through the stop file", "normal stop · scheduled task deleted" in out)
        m = re.search(r"Created file: (.+\.zip)", out)
        check(stage, "create the collection zip", bool(m) and rc == 0,
              m.group(1).strip() if m else "rc=%d" % rc)
        if not m:
            raise SystemExit("The collection zip was not created.")
        zp = pathlib.Path(m.group(1).strip())
        try:
            with zipfile.ZipFile(zp) as zf:
                ledger = json.loads(zf.read("chains/_device.chain.json").decode("utf-8"))
        except (OSError, KeyError, ValueError, zipfile.BadZipFile):
            ledger = None
        judge_chains("3 device precollection check", chain_blocks(out), tag, ledger)
    check(stage, "after collection: no scheduled task · 0 service processes",
          not task_exists() and not service_lines())

    heading("[3] Organization: receive the collection -- manifest, certificate, seal signature, "
            "verify with the root key (C1–C4)")
    shutil.copy2(zp, ORGD / zp.name)
    old_received = ORG / "received" / zp.stem
    if old_received.exists():
        old_received.rename(old_received.with_name(
            old_received.name + "_previous_attempt_" + datetime.datetime.now().strftime("%H%M%S")))
    rc, out = run([PY, ORG_SRC / "side_org.py", "receive", ORGD / zp.name, "--custody", st["custody"],
                   "--seal-private-key", ORG / "org_keys" / SEAL_SECRET_NAME], cwd=ORG)
    stage = "3 organization receive"
    check(stage, "0 files differ from the manifest",
          bool(re.search(r"(?<!\d)0 differ from the manifest", out)))
    check(stage, "enrollment certificate and seal public key match the custody copy",
          "enrollment certificate match · seal public key match" in out)
    check(stage, "root key commitment match", "root key commitment match" in out)
    sigs = []
    capturing = False
    for l in out.splitlines():
        s = l.strip().lstrip("|").strip()
        if s.lower().startswith("seal signature"):
            capturing = True
            continue
        if capturing:
            if not s:
                break
            sigs.append(s)
    valid = sum(1 for s in sigs if re.search(r"\bvalid$", s))
    check(stage, "every seal the organization signed is valid", bool(sigs) and valid == len(sigs),
          "%d valid of %d" % (valid, len(sigs)))
    blocks = chain_blocks(out)
    received = ORG / "received" / zp.stem
    try:
        ledger = load(received / CHAINS_DIR / LEDGER_NAME)
    except (OSError, ValueError):
        ledger = None
    judge_chains(stage, blocks, tag, ledger)
    check(stage, "verification_result.txt", None, str(received / "verification_result.txt"))

    heading("[4] Organization: disclosure package -- records 1 to 5 of the normal session")
    stage = "3 disclosure"
    normal, _ = find_block(blocks, "normal", tag)
    out_dir = ORG / "disclosures"
    before = set(out_dir.glob("*.json")) if out_dir.exists() else set()
    rc, out = run([PY, ORG_SRC / "side_org.py", "disclose", "--collection", received,
                   "--chain", normal or "?",
                   "--range", "1-5", "--rule", "field test normal session"], cwd=ORG)
    new = sorted(set(out_dir.glob("*.json")) - before) if out_dir.exists() else []
    pkg = new[-1] if new else None
    check(stage, "make the disclosure package", rc == 0 and pkg is not None, str(pkg))
    check(stage, "gap report and scope statement are included", "gap report" in out.lower())
    if not pkg:
        raise SystemExit("The disclosure package was not created.")

    heading("[5] Verifier: verify the package with the separately received public key")
    stage = "3 verifier"
    pub = ORG / SEAL_PUB_NAME
    rc, out = run([PY, ORG_SRC / "side_org.py", "verify-package", pkg, "--seal-public-key", pub], cwd=ORG)
    check(stage, "correct public key → pass", rc == 0)
    check(stage, "gap report has no 'without the backup privilege' notice",
          "without the backup privilege" not in out)
    v = pub.read_text(encoding="utf-8").strip()
    wrong = ORGD / "test_wrong_public_key.hex"
    wrong.write_text(v[:-1] + ("0" if v[-1] != "0" else "1"), encoding="utf-8")
    rc, _ = run([PY, ORG_SRC / "side_org.py", "verify-package", pkg, "--seal-public-key", wrong],
                cwd=ORG, show=False)
    check(stage, "wrong public key → rejected", rc != 0, "rc=%d" % rc)
    original_pkg = load(pkg)

    def flip_last(s: str) -> str:
        return s[:-1] + ("0" if s[-1] != "0" else "1")

    def edit_record(d: dict) -> None:
        rec = d["items"][0]["record"]
        k = next(k for k in sorted(rec) if isinstance(rec[k], str) and rec[k])
        rec[k] = flip_last(rec[k])

    def lower_count(d: dict) -> None:
        d["total_entries"] = int(d["total_entries"]) - 1

    def verify_tampered(name: str, edit, must_reject: bool) -> None:
        d = json.loads(json.dumps(original_pkg))
        try:
            edit(d)
        except (KeyError, IndexError, TypeError, ValueError, StopIteration) as e:
            check(stage, name, False, "the field to change is not in the package: %s %s"
                  % (e.__class__.__name__, e))
            return
        p = ORGD / ("test_tampered_package_%d.json" % (len(results)))
        save(p, d)
        rc, _ = run([PY, ORG_SRC / "side_org.py", "verify-package", p, "--seal-public-key", pub],
                    cwd=ORG, show=False)
        check(stage, name, (rc != 0) if must_reject else None, "rc=%d" % rc)

    verify_tampered("package with one character of the seal body (final_tag) changed → rejected "
                    "(the seal signature catches it)",
                    lambda d: d["seal"]["body"].__setitem__(
                        "final_tag", flip_last(d["seal"]["body"]["final_tag"])),
                    True)
    verify_tampered("package with one character of the seal signature value changed → rejected",
                    lambda d: d["seal"]["sig"].__setitem__("value", flip_last(d["seal"]["sig"]["value"])),
                    True)
    verify_tampered("package with one character of a disclosed record changed → rejected "
                    "(the Merkle proof catches it)", edit_record, True)
    verify_tampered("package that reports a lower total record count → rejected "
                    "(checked against the count in the seal body)", lower_count, True)
    verify_tampered("package with only the seal HMAC tag (seal.tag) changed → passes by design "
                    "(no recomputation without the root key)",
                    lambda d: d["seal"].__setitem__("tag", flip_last(d["seal"]["tag"])), False)
    check(stage, "inspect it in the viewer", None,
          "%s → paste the value of %s into the public key field → [package view] %s"
          % (VIEW / "1_viewer.bat", pub.name, pkg.name))
    return finish(0)


def report(rows: list[dict]) -> str:
    out = []
    stage = None
    for r in rows:
        if r["stage"] != stage:
            stage = r["stage"]
            out.append("\n[%s]" % stage)
        out.append("  %-4s %s%s" % ({True: "PASS", False: "FAIL", None: "INFO"}[r["ok"]], r["items"],
                                   ("  -- " + r["detail"]) if r["detail"] else ""))
    return "\n".join(out) + "\n"


def finish(rc: int) -> int:
    rows = (load(R1) if R1.exists() else []) + (load(EMP)["result"] if EMP.exists() else []) + results
    p, f = sum(r["ok"] is True for r in rows), sum(r["ok"] is False for r in rows)
    head = ("SIDE field test summary · %s\nPC %s · employee %s · Python %s\nPASS %d · FAIL %d\n"
            % (datetime.datetime.now().isoformat(timespec="seconds"), os.environ.get("COMPUTERNAME"),
               load(STATE)["employee"] if STATE.exists() else "?", sys.version.split()[0], p, f))
    text = head + report(rows)
    name = "test_summary_%s.txt" % datetime.datetime.now().strftime(STAMP)
    for d in (HERE, ORGD):
        try:
            (d / name).write_text(text, encoding="utf-8")
        except OSError:
            pass
    heading("Test done -- PASS %d · FAIL %d" % (p, f))
    for r in rows:
        if r["ok"] is False:
            say("  FAIL [%s] %s  %s" % (r["stage"], r["items"], r["detail"]))
    say("\n  Result file: %s" % (HERE / name))
    say("  Send only this file.  (Do not send the collection zip.  It contains the original conversations.)")
    say("  To clean up, run 9_admin_cleanup.bat")
    return rc


def _rm(p: pathlib.Path) -> None:
    def onerr(fn, path, _):
        os.chmod(path, stat.S_IWRITE)
        fn(path)
    if p.is_dir():
        shutil.rmtree(p, onerror=onerr)
    elif p.exists():
        p.unlink()


def cleanup() -> int:
    heading("SIDE field test cleanup")
    if not is_admin():
        raise SystemExit("Administrator rights are required.")
    say("  Deletes: scheduled task SIDE, %s, %s\\SIDE_previous_install_*, %s, %s, %s,"
        % (BASE, PD, INST, ORGD, PUB))
    say("           and in the employee account .claude\\projects\\side-test-* and side-test "
        "(test logs · first.jsonl of the manual walkthrough)")
    say("  Keeps: test_summary_*.txt in this folder")
    if ask("  Delete? (y/N): ").lower() != "y":
        return 0
    cleanup_run()
    return 0


def cleanup_run() -> None:
    if (DEV_SRC / "side_device.py").exists() and (task_exists() or service_lines()):
        run([PY, DEV_SRC / "side_device.py", "uninstall"], cwd=DEV)
    elif task_exists():
        sysrun(["schtasks", "/End", "/TN", TASK])
        sysrun(["schtasks", "/Delete", "/TN", TASK, "/F"])
    projects = employee_projects()
    if service_lines():
        ps("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*side_service*--watch*' } | "
           "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }")
        time.sleep(2)
    for p in [BASE, *PD.glob("SIDE_previous_install_*"), INST, ORGD, PUB]:
        if p.exists():
            sysrun(["takeown", "/F", p, "/R", "/D", "Y"])
            sysrun(["icacls", p, "/reset", "/T", "/C"])
        try:
            _rm(p)
            say("    deleted %s" % p)
        except OSError as e:
            say("    ! could not delete %s (%s)" % (p, e))
    if projects:
        for p in [*projects.glob("side-test-*"), projects / "side-test"]:
            if not p.exists():
                continue
            sysrun(["icacls", p, "/reset", "/T"])
            try:
                _rm(p)
                say("    deleted %s" % p)
            except OSError as e:
                say("    ! could not delete %s (%s)" % (p, e))
    say("\n  Cleanup done.  Scheduled task: %s" % ("still present (!)" if task_exists() else "none"))


def employee_projects() -> pathlib.Path | None:
    pattern = load(STATE).get("pattern", []) if STATE.exists() else []
    return pathlib.Path(pattern[0]).parent.parent if pattern else None


def status_text() -> str:
    if not (DEV_SRC / "side_device.py").exists() or not is_admin():
        return ""
    return run([PY, DEV_SRC / "side_device.py", "status"], cwd=DEV, show=False)[1]


def diagnose(reason: str = "") -> pathlib.Path:
    lines = ["SIDE field test diagnosis · %s" % datetime.datetime.now().isoformat(timespec="seconds"),
             "reason: %s" % (reason or "(diagnose only)"), "",
             "PC %s · account %s · administrator rights %s"
             % (os.environ.get("COMPUTERNAME"), os.environ.get("USERNAME"), is_admin()),
             "Python %s · %s" % (sys.version.split()[0], PY),
             "Windows %s · OEM %s" % (sysrun(["cmd", "/c", "ver"])[1], OEM), ""]
    for p in (INST, ORGD, PUB, BASE, DEV / SEAL_PUB_NAME, STATE, EMP):
        lines.append("%-60s %s" % (p, "present" if p.exists() else "absent"))
    lines += ["", "-- Python for all users"]
    lines += [str(p) for p in pathlib.Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
              .glob("Python3*/python.exe")]
    lines += ["", "-- scheduled task", sysrun(["schtasks", "/Query", "/TN", TASK, "/V", "/FO", "LIST"])[1]]
    try:
        lines += ["", "-- service processes"] + (service_lines() or ["(none)"])
    except Exception as e:
        lines.append("(could not read %s)" % e)
    if is_admin():
        try:
            lines += ["", "-- side_device status", status_text()]
        except Exception as e:
            lines.append("(could not read status %s)" % e)
        for f in ("install.json", "whoami.txt", "store_acl.txt", "restart.log", "service.log",
                  "org/enroll.log"):
            q = BASE / f
            if q.exists():
                try:
                    raw = q.read_bytes()
                    try:
                        t = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        t = raw.decode(OEM, errors="replace")
                    lines += ["", "-- %s" % q, t[-4000:]]
                except OSError as e:
                    lines += ["", "-- %s could not be read %s" % (q, e)]
        if (BASE / "store").exists():
            lines += ["", "-- service folder permissions", sysrun(["icacls", BASE / "store"])[1]]
            try:
                ent = load(BASE / "store" / CHAINS_DIR / LEDGER_NAME).get("entries", [])
                lines += ["", "-- last 20 ledger records (total %d)" % len(ent)]
                for e in ent[-20:]:
                    r = e.get("record") or {}
                    lines.append("  %s  %-14s %s %s" % (_clock(_utc(r.get("ts_recorded"))), r.get("kind", ""),
                                                      r.get("session_file", "") or r.get("what", ""),
                                                      r.get("reason", "") or r.get("error", "")))
            except Exception as e:
                lines.append("(could not read the ledger %s)" % e)
            try:
                lines += ["", "-- chain files",
                          "\n".join("  %s %d" % (c.name, c.stat().st_size)
                                    for c in sorted((BASE / "store" / CHAINS_DIR).glob("*.json")))]
            except OSError as e:
                lines.append("(could not list the chains %s)" % e)
    try:
        projects = employee_projects()
        if projects:
            lines += ["", "-- files in the employee session folder (attributes · size)",
                      ps("Get-ChildItem -Force -Recurse '%s' -ErrorAction SilentlyContinue | "
                         "Select-Object -First 60 | ForEach-Object { '{0}  {1}  {2}' -f $_.Attributes, "
                         "$_.Length, $_.FullName }"
                         % str(projects).replace("'", "''"))]
    except Exception as e:
        lines.append("(could not list the employee folder %s)" % e)
    if results:
        lines += ["", "-- checks from this run", report(results)]
    if LOG and LOG.exists():
        lines += (["", "-- screen log (last 300 lines)"]
                  + LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-300:])
    f = writable_dir() / ("test_diagnosis_%s.txt" % datetime.datetime.now().strftime(STAMP))
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f


USAGE = """usage: python side_test.py {install,employee,collect,cleanup,diagnose}

  install    administrator: install SIDE and check the deployment (1_admin_install.bat)
  employee   employee: write session logs and attack the service (2_employee_test.bat)
  collect    administrator: collect, receive, disclose, verify (3_admin_collect_and_verify.bat)
  cleanup    administrator: remove everything the test created (9_admin_cleanup.bat)
  diagnose   write the current state into test_diagnosis_<time>.txt (0_diagnose.bat)"""


def main() -> int:
    global LOG
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd in ("-h", "--help"):
        print(USAGE)
        return 0
    if os.name != "nt":
        raise SystemExit("Runs on Windows only.")
    jobs = {"install": install, "employee": employee, "collect": collect, "cleanup": cleanup,
            "diagnose": lambda: 0}
    if cmd not in jobs:
        say(USAGE)
        return 2
    if cmd != "employee":
        load_util()
    LOG = writable_dir() / ("test_log_%s_%s.log" % (cmd, datetime.datetime.now().strftime(STAMP)))
    console = console_utf8()
    try:
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write("console: %s · OEM %s\n" % (console, OEM))
    except OSError:
        pass
    reason = ""
    try:
        rc = jobs[cmd]()
        if cmd == "diagnose":
            reason = "0_diagnose run"
        elif rc:
            reason = "%s ended with rc=%s" % (cmd, rc)
    except KeyboardInterrupt:
        rc, reason = 130, "stopped by the user (Ctrl+C)"
    except SystemExit as e:
        if isinstance(e.code, int) or e.code is None:
            rc = e.code or 0
        else:
            say("\n  ! " + str(e.code))
            rc, reason = 1, str(e.code)
    except Exception:
        import traceback
        tb = traceback.format_exc()
        say("\n  ! An unexpected error occurred.\n" + tb)
        rc, reason = 1, "exception\n" + tb
    if reason:
        try:
            f = diagnose(reason)
            say("")
            say("-" * RULE)
            if cmd == "diagnose":
                say("  Diagnosis file: %s" % f)
            else:
                say("  Something went wrong.  The current state is collected in one file:")
                say("    %s" % f)
                say("  Send this file and we will look for the cause.  "
                    "You can also run the same bat file again")
                say("  (1 removes what is left and starts over, "
                    "3 skips the stages that finished and continues).")
            say("-" * RULE)
        except Exception as e:
            say("  The diagnosis file could not be created either: %s" % e)
    return rc


if __name__ == "__main__":
    sys.exit(main())
