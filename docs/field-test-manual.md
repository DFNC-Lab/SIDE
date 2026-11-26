# SIDE field test: manual walkthrough

This walkthrough does by hand what the `field-test\` bat files do, one command at a time. Use it when a bat
file gets stuck, or to see each step of Phase 0 Enrollment, Phase 1 Binding at creation time, and Phase 2
Sealing, disclosure, and verification on a real Windows PC. Never run it on a work PC.

이 문서는 `field-test\` bat 파일이 하는 일을 명령 하나씩 손으로 합니다. bat 파일이 멈췄을 때, 또는 0단계 가입,
1단계 생성 시점 묶기, 2단계 봉인·제출·검증의 각 단계를 실제 Windows PC에서 직접 보고 싶을 때 씁니다.
업무용 PC에서는 절대 하지 마십시오.

This document installs SIDE on one PC and walks one full round. It checks that the employee's attempts to
stop, delete or edit are blocked or revealed. It then follows the organization from collection to the
disclosure to a verifier. Work through it from top to bottom, one line at a time.
The whole run takes about 1 hour 30 minutes, including the reboot and battery tests.

The automated version of this test is in `field-test/` (see `field-test/README.md`). The screen texts quoted
below show the expected content. The exact wording on your screen can differ slightly.

---

## 0. Read first / 먼저 읽기

### 0.1 Roles: three roles, two accounts

| Role | In a real deployment | In this test | Account |
|---|---|---|---|
| **administrator** | IT administrator. Installs on and collects from employee PCs | the tester | the usual **administrator account** (`admin` below) |
| **employee** | the person whose sessions are logged. Uses an AI coding tool | the tester, after switching accounts | a new **standard user** `sidetest` |
| **organization and verifier** | another machine of the organization, an external verifier | the administrator account on the same PC | `admin` |

The test has no separate organization machine. The organization files therefore live in a folder locked
against the employee (`C:\SIDE_org_side`). In a real deployment this folder sits on another machine.

### 0.2 Windows: five kinds

| Label | How to open | Who |
|---|---|---|
| **admin PowerShell** | Start → type `powershell` → right click *Windows PowerShell* → **Run as administrator** → *Yes* in User Account Control | administrator |
| **plain PowerShell** | Start → type `powershell` → Enter (no administrator rights) | employee / administrator |
| **bat (self-elevating)** | double click an `employee\` bat file in Explorer → it reopens itself as administrator → *Yes* in User Account Control | administrator |
| **bat (plain)** | double click the bat file in Explorer | administrator |
| **viewer window** | double click `verifier\1_viewer.bat` (or `organization\5_viewer.bat`) → the "SIDE viewer (read only)" window | administrator |

A window with administrator rights has **"Administrator:"** in its title.

### 0.3 Folders and who can open them

| Folder | Contents | Who can open it |
|---|---|---|
| `C:\SIDE_install\employee\` | install bundle. The collection zip also appears here in `collections\` | SYSTEM · administrator |
| `C:\SIDE_org_side\organization\` | organization tools · **seal private key** · received collections · disclosure files | SYSTEM · administrator |
| `C:\SIDE_org_side\verifier\` | verifier tool | SYSTEM · administrator |
| `C:\SIDE_org_side\SIDE_custody_<device>_<time>\` | the device's **root key K0** · enrollment certificate (created during install) | SYSTEM · administrator |
| `C:\ProgramData\SIDE\` | service folder (the install creates and locks it) | SYSTEM · Administrators (only from a window with administrator rights) |
| `C:\Users\sidetest\.claude\projects\…` | employee session logs (the logged data) | employee · SYSTEM · administrator |

### 0.4 How to record results

Each step lists **what should appear**. Tick ☑ when it matches. When it differs, copy the screen as it is.
Collect those copies for "What to send" at the end.

---

## 1. Preparation / 준비 (administrator, 20 min)

> Who: **administrator** · Where: the PC, logged in with the administrator account

**1-1. Put the repository on the test PC**
- Where: Explorer, or `git clone` in a PowerShell window
- What to do: copy the whole repository to `C:\SIDE_source\`. The steps below use its `employee\`,
  `organization\`, `verifier\` and `src\` folders.
- What should appear: `C:\SIDE_source\employee\`, `C:\SIDE_source\organization\`, `C:\SIDE_source\verifier\` and `C:\SIDE_source\src\` exist. ☐

**1-2. Create the employee account**
- Where: **admin PowerShell**
- Type (one line at a time):
  ```powershell
  $pw = Read-Host -AsSecureString "password for sidetest"
  New-LocalUser -Name sidetest -Password $pw -FullName "SIDE test employee" -PasswordNeverExpires
  Add-LocalGroupMember -SID S-1-5-32-545 -Member sidetest
  Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name
  ```
- What should appear: the last command lists the Administrators members, and `sidetest` is **not** among
  them. The account is therefore a standard user. ☐
- The Settings app also works: Settings → Accounts → Other users → Add account → "I don't have this person's
  sign-in information" → "Add a user without a Microsoft account" → keep the account type *Standard User*.

**1-3. Install Python for all users**
- Where: browser → python.org → Downloads → Windows → *Windows installer (64-bit)* (3.10 or later, for example 3.13)
- What to do: run the installer, then
  1. on the first screen, tick **Use admin privileges when installing py.exe** and **Add python.exe to PATH**
  2. **Customize installation** → Next
  3. under Advanced Options tick **Install Python 3.13 for all users** → check that the install location
     changes to `C:\Program Files\Python313` → Install
- What should appear: "Setup was successful". ☐

**1-4. Check the Python that SIDE will use**
- Where: **admin PowerShell** (a new window opened after 1-3)
- Type:
  ```powershell
  py -3 -c "import sys; print(sys.executable, sys.version)"
  Get-ChildItem "C:\Program Files\Python3*\python.exe"
  ```
- What should appear: the first line is `C:\Program Files\Python313\python.exe 3.13.…`. The second command
  lists the same file. ☐
- If the first line is `C:\Users\…\AppData\…`: remove that Python in Settings → Apps → Installed apps and
  check again. If you cannot remove it, call the python.exe in Program Files directly, as in 3-4 below.

**1-5. Create two folders and lock them against the employee**
- Where: **admin PowerShell**
- Type:
  ```powershell
  New-Item -ItemType Directory C:\SIDE_install, C:\SIDE_org_side | Out-Null
  foreach ($d in "C:\SIDE_install", "C:\SIDE_org_side") {
    icacls $d /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
  }
  Copy-Item -Recurse C:\SIDE_source\employee     C:\SIDE_install\employee
  Copy-Item -Recurse C:\SIDE_source\organization C:\SIDE_org_side\organization
  Copy-Item -Recurse C:\SIDE_source\verifier     C:\SIDE_org_side\verifier
  Copy-Item -Recurse C:\SIDE_source\src          C:\SIDE_install\src
  Copy-Item -Recurse C:\SIDE_source\src          C:\SIDE_org_side\src
  Get-ChildItem -Recurse C:\SIDE_install, C:\SIDE_org_side | Unblock-File
  icacls C:\SIDE_org_side
  ```
- What should appear:
  - `C:\SIDE_install\employee\1_install.bat`, `C:\SIDE_org_side\organization\1_make_seal_key.bat` and
    `C:\SIDE_org_side\verifier\1_viewer.bat` exist ☐
  - the last `icacls` lists only three entries: the administrator account · `NT AUTHORITY\SYSTEM` ·
    `BUILTIN\Administrators`. `Users` is absent ☐
- Why the administrator account is the third entry: with only the Administrators group, the administrator
  can open this folder only from a window with administrator rights. Explorer and bat files without administrator rights would be blocked.

---

## 2. First use of the employee account / 직원 계정 첫 사용 (employee, 10 min)

> Who: **employee** · Where: the PC, logged in as `sidetest`

**2-1. Leave the administrator account**
- Where: administrator account → Start → user icon → **Sign out**. Switching users also works, but signing
  out avoids confusion during the test.

**2-2. Log in as `sidetest`**
- Where: the user list at the bottom left of the sign in screen → *SIDE test employee* → the password from 1-2
- What should appear: the preparation for the first sign in finishes and the desktop appears (`C:\Users\sidetest` now exists) ☐

**2-3. Create one session log to be logged**
- Where: **plain PowerShell** (employee)
- If you can use the real Claude Code: install it with `irm https://claude.ai/install.ps1 | iex` → in a new
  PowerShell run `mkdir $HOME\work; cd $HOME\work; claude` → sign in → say "hello" once → `/exit`.
- Without an account (recommended, and section 5 uses the same method): create a synthetic session file in the
  same place Claude Code uses.
  ```powershell
  $d = "$HOME\.claude\projects\side-test"
  New-Item -ItemType Directory -Force $d | Out-Null
  function Add-Line($name, $n) { [IO.File]::AppendAllText("$d\$name", "{`"type`":`"user`",`"n`":$n,`"t`":`"$(Get-Date -Format o)`"}`n") }
  1..3 | ForEach-Object { Add-Line "first.jsonl" $_ }
  Get-ChildItem $d
  ```
- What should appear: `first.jsonl` is listed ☐

**2-4. Sign out**: Start → user icon → Sign out

---

## 3. Organization key and install / 조직 키와 설치 (administrator, 15 min)

> Who: **administrator** · Where: log in again with the administrator account · Phase 0 Enrollment

**3-1. [organization] Make the seal key pair**
- Where: Explorer → `C:\SIDE_org_side\organization\` → **double click `1_make_seal_key.bat`** (bat plain)
- What should appear (black window), with content like:
  ```
      seal key pair → C:\SIDE_org_side\organization\org_keys
        public key <64 hex digits>  (device enrollment --seal-pubkey …\org_keys\seal_pub.hex)
        the private key is only in …\org_keys\seal_secret.hex -- not printed on screen

    For the device   : C:\SIDE_org_side\organization\seal_pub.hex
                       Put it into the employee folder on the employee PC and run employee\1_install.bat.
    For the verifier : the same public key (send it separately from the disclosure package)
    Private key      : C:\SIDE_org_side\organization\org_keys\seal_secret.hex.  Never let it leave this machine.
  ```
  Press any key to close the window. ☐

**3-2. [organization → administrator] Put only the seal public key into the employee bundle**
- Where: **admin PowerShell**
- Type:
  ```powershell
  Copy-Item C:\SIDE_org_side\organization\seal_pub.hex C:\SIDE_install\employee\
  Get-Content C:\SIDE_install\employee\seal_pub.hex
  Test-Path C:\SIDE_install\employee\seal_secret.hex
  ```
- What should appear: one line of 64 hex digits · the last line `False` (the private key is not in the employee bundle) ☐

**3-3. Write down the exact path of the Python that installs SIDE**
- Where: the same admin PowerShell
- Type: `(Get-ChildItem "C:\Program Files\Python3*\python.exe").FullName`
- What should appear: for example `C:\Program Files\Python313\python.exe`. The steps below use this value ☐

**3-4. Install, naming the employee account**
- Where: the same admin PowerShell
- Type (use the path from 3-3):
  ```powershell
  cd C:\SIDE_install\employee
  & "C:\Program Files\Python313\python.exe" ..\src\side_device.py install --employee sidetest
  ```
- Why the command line: `employee\1_install.bat` also works here if you type `sidetest` at its question
  "Employee account to bind". Pressing Enter there binds the **account signed in now**, which is the
  administrator, so the test would prove nothing. The command line names the employee and the Python from 3-3
  explicitly. In a real deployment the employee is signed in on the employee PC, and the administrator
  double clicks `1_install.bat`, approves User Account Control, and presses Enter.
- What should appear (in this order), with content like:
  ```
  ==============================================================
    SIDE install
  ==============================================================
    Employee account : sidetest
    Profile          : C:\Users\sidetest
    Python           : C:\Program Files\Python313\python.exe
    Service folder   : C:\ProgramData\SIDE\store
    Seal public key  : <16 hex digits>…
    Binding range    :
        C:\Users\sidetest\.claude\projects\*\*.jsonl
        C:\Users\sidetest\.codex\sessions\**\*.jsonl
        C:\Users\sidetest\.gemini\antigravity\brain\*\.system_generated\logs\transcript*.jsonl
        C:\Users\sidetest\.gemini\antigravity-cli\brain\*\.system_generated\logs\transcript*.jsonl

    Registered and started the scheduled task 'SIDE' under the SYSTEM account (starts at every boot).
    Waiting for enrollment…
    Device enrollment complete.  The service started binding (the first binding takes a few minutes, …).

  --------------------------------------------------------------
    Moving the root key K0 off the device.  Until it moves, anyone who copies K0
    …
    Destination folder (leave empty to run employee\2_move_root_key.bat later):
  ```
  ☐

**3-5. Move the root key to the organization side**
- Where: the same window, answering the question from 3-4
- Type: `C:\SIDE_org_side` Enter
  (In a real deployment, enter a USB path such as `E:\` and carry the USB drive to the organization machine.)
- What should appear, with content like:
  ```
    Root key moved: C:\SIDE_org_side\SIDE_custody_<device>_<time>
    The device copy of the root key was overwritten and deleted.
    The device now holds only the current stage key of each chain.
  ```
  ☐
- Check: `Get-ChildItem C:\SIDE_org_side\SIDE_custody_*` → `k0.hex` · `enroll.json` · `seal_pub.hex` · `00_README.txt` ☐

---

## 4. Deployment check / 배포 확인 (administrator, 15 min + reboot)

> Who: **administrator** · Where: administrator account. Steps 4-2 to 4-6 use **admin PowerShell**

**4-1. Show the status**
- Where: Explorer → `C:\SIDE_install\employee\` → **double click `3_status.bat`** → *Yes* in User Account Control (bat self-elevating)
- What should appear, with content like:
  ```
    Scheduled task 'SIDE' : registered
    Service processes  : 1 (normal)
    Install            : <time> · employee sidetest · <revision, REVISION in src\side_core.py>
    Ledger             : N records · last …
                         <record kinds and counts>
    Session chains     : 1 or more   (first.jsonl from 2-3)
    Root key copy      : not on the device
  ```
  ☐

**4-2. Does the service run as SYSTEM with backup read?**
```powershell
Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object CommandLine -like '*side_service*' |
  ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User; $_.CommandLine }
```
- What should appear: one line `SYSTEM`, and a command line with `--watch` · `--read-mode backup` ·
  `--restart-on-error 5` · `C:\Users\sidetest\…` ☐

**4-3. Scheduled task settings**
```powershell
schtasks /Query /TN SIDE /V /FO LIST | Select-String "Run As User|Schedule Type|Status"
```
- What should appear: Run As User `SYSTEM` · Schedule Type "At system start up" · Status "Running" ☐

**4-4. Is the service folder locked?**
```powershell
icacls C:\ProgramData\SIDE; icacls C:\ProgramData\SIDE\store; icacls C:\ProgramData\SIDE\org; icacls C:\ProgramData\SIDE\bin
```
- What should appear: all four list only `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
  `Users`, `Authenticated Users` and `sidetest` are absent ☐

**4-5. Records the service wrote itself**
```powershell
Get-Content C:\ProgramData\SIDE\whoami.txt
Get-Content C:\ProgramData\SIDE\store_acl.txt
Get-ChildItem -Recurse C:\ProgramData\SIDE -Filter "*k0*"
```
- What should appear: first line `nt authority\system` (followed by `S-1-5-18`) · `store_acl.txt` contains
  "Successfully processed 1 files; Failed processing 0 files" · the last command prints **nothing** ☐

**4-6. Are the chains bound so far correct (without the root key)?**
```powershell
$env:SIDE_STORE = "C:\ProgramData\SIDE\store"
& "C:\Program Files\Python313\python.exe" C:\ProgramData\SIDE\bin\side_service.py --verify
```
- What should appear: `OK` for every session chain. `_device.chain.json` shows `FAIL`, and its only two
  signals are "no service_stop yet" and "service_start at seq 1 is still open". The service is running, so
  its last start has no stop yet, which is normal. The ledger shows one service interval. **No line about a
  service interval read "without the backup privilege" appears** ☐
  (If that line appears, the service reads without the backup privilege. Send that screen.)

**4-7. Does the service come back on its own after a reboot?**
- What to do: Start → Power → Restart → log in with the administrator account (**do not log in with the
  employee account**) → double click `3_status.bat` → *Yes*
- The service starts about 2 minutes after boot. Wait until the ledger shows a service_start with a time
  after the reboot, then go to the next step.
- What should appear: service processes 1 (normal) · `service_start 2` among the ledger record kinds ☐
  (A reboot cuts the service without a stop record. At collection the ledger therefore shows "1 interval
  ended without a stop" and "service_start at seq 1 has no matching service_stop". The automated test
  (stage 3) counts this as PASS when the Windows System log has a boot record in between.)

**4-8. (laptops only) Does it keep running on battery?**
- What to do: unplug the power cable, wait 5 minutes, double click `3_status.bat` → *Yes* → plug it back in
- What should appear: service processes 1 ☐

**4-9. Sign out**

---

## 5. Employee work and attacks / 직원 작업과 공격 (employee, 25 min)

> Who: **employee** · Where: log in as `sidetest` → open one **plain PowerShell** and use it to the end · Phase 1 Binding at creation time.
> The employee tries everything possible on the own PC. Attempts to stop the service **must be blocked**.
> Editing the own logs **cannot be blocked, but collection must reveal it**.

**5-0. Prepare the tools for this window** (recreate the function from 2-3)
```powershell
$d = "$HOME\.claude\projects\side-test"
New-Item -ItemType Directory -Force $d | Out-Null
function Add-Line($name, $n) { [IO.File]::AppendAllText("$d\$name", "{`"type`":`"user`",`"n`":$n,`"t`":`"$(Get-Date -Format o)`"}`n") }
```

### 5-A. Normal work: it must be bound

**5-1. Normal session**
```powershell
1..20 | ForEach-Object { Add-Line "normal.jsonl" $_; Start-Sleep 1 }
```
- What should appear: the prompt returns after 20 seconds. (If you can use the real Claude Code, a normal
  conversation of about 10 minutes also works.) ☐

### 5-B. Attempts to stop the service: every one must be blocked

Type one line at a time and copy each result as it is.

| # | Type | What should appear | ☐ |
|---|---|---|---|
| 5-2 | `schtasks /End /TN SIDE` | `ERROR: Access is denied.` | ☐ |
| 5-3 | `schtasks /Delete /TN SIDE /F` | `ERROR: Access is denied.` | ☐ |
| 5-4 | `Get-Process python, pythonw -ErrorAction SilentlyContinue \| Stop-Process -Force` | "Access is denied" for the SYSTEM python (only a python the employee started, if any, ends) | ☐ |
| 5-5 | `Get-ChildItem C:\ProgramData\SIDE` | "Access to the path … is denied" | ☐ |
| 5-6 | `Set-Content C:\ProgramData\SIDE\org\STOP stop` | access denied (the employee cannot place the stop file) | ☐ |
| 5-7 | `Remove-Item C:\ProgramData\SIDE\store\chains\_device.chain.json` | access denied (the employee cannot delete the ledger) | ☐ |
| 5-8 | `Get-ChildItem C:\ProgramData\SIDE\store\keys` | access denied (the employee cannot see the keys) | ☐ |
| 5-9 | `Add-Content C:\ProgramData\SIDE\bin\watch.cmd "rem x"` | access denied (the employee cannot change the service code) | ☐ |
| 5-10 | `takeown /F C:\ProgramData\SIDE` | an error saying the current user lacks ownership privileges, or access denied | ☐ |
| 5-11 | `icacls C:\ProgramData\SIDE /grant "${env:USERNAME}:F"` | `Access is denied.` and `Failed processing 1 files` (the employee cannot open the service folder to itself) | ☐ |
| 5-12 | `Get-Content C:\SIDE_org_side\organization\org_keys\seal_secret.hex` | access denied (test layout check: the employee cannot see the seal private key) | ☐ |
| 5-13 | `Get-ChildItem C:\SIDE_org_side` | access denied (the employee cannot open the organization side, where the root key custody copy is) | ☐ |
| 5-14 | `Get-ChildItem C:\SIDE_install` | access denied (the employee cannot open the install folder) | ☐ |

### 5-C. Attempts to touch the own logs: they cannot be blocked, but they must be revealed

The employee owns the session files and can edit and delete them. SIDE does not block this. **Collection
verification reveals it.** Each of the three attempts below uses a different file, so `normal.jsonl` stays clean.

**5-15. Change one character after binding → C3 must catch it**
```powershell
1..10 | ForEach-Object { Add-Line "tamper.jsonl" $_ }
Start-Sleep 10
$s = [IO.File]::Open("$d\tamper.jsonl", 'Open', 'ReadWrite'); $s.Position = 19; $s.WriteByte([byte][char]'9'); $s.Close()
Get-Content "$d\tamper.jsonl" -TotalCount 1
```
- What should appear: `"n":1` in the first line now reads `"n":9` (the size stays the same) ☐

**5-16. Delete the file after binding → it must show as source absent**
```powershell
1..5 | ForEach-Object { Add-Line "delete.jsonl" $_ }
Start-Sleep 10
Remove-Item "$d\delete.jsonl"
```
- What should appear: the file is deleted without any error ☐

**5-17. Deny read to SYSTEM and keep writing → it must still be bound (backup read)**
```powershell
1..3 | ForEach-Object { Add-Line "denyread.jsonl" $_ }
Start-Sleep 10
icacls "$d\denyread.jsonl" /deny "*S-1-5-18:(R)"
4..6 | ForEach-Object { Add-Line "denyread.jsonl" $_ }
Start-Sleep 10
```
- What should appear: `icacls` reports "Successfully processed 1 files" · the later appends show no error ☐
  (The service reads with the backup privilege. It must bypass this deny entry and bind all 6 lines.
  Section 7 checks this.)

**5-18. Save the screen and leave**
- What to do: select the whole content of the PowerShell window, paste it into Notepad and save it as
  `C:\Users\sidetest\Desktop\attack_result.txt` (the administrator picks it up later) → close all AI tools
  → **Sign out**

---

## 6. Administrator check and collection / 관리자 확인과 수거 (administrator, 10 min)

> Who: **administrator** · Where: log in with the administrator account · Phase 2 Sealing, disclosure, and verification begins

**6-1. Is the service unchanged after the attacks?**
- Where: double click `C:\SIDE_install\employee\3_status.bat` → *Yes*
- What should appear: service processes 1 (normal) · more ledger records than in 4-7 · 5 session chains
  (first · normal · tamper · delete · denyread) · **no** restart count line (or 0) ☐

**6-2. Pick up the employee's attack results**
- Where: admin PowerShell
- Type: `Copy-Item C:\Users\sidetest\Desktop\attack_result.txt C:\SIDE_org_side\`

**6-3. Collect**
- Where: **double click `C:\SIDE_install\employee\4_collect.bat`** → *Yes* in User Account Control
- At the question asking for 1 or 2, type `2` Enter (include the session logs. This is a test PC, so the
  conversation text may leave it.)
- What should appear (in this order), with content like:
  ```
  [1/5] Stopping the service (stop file)
      normal stop · scheduled task deleted
  [2/5] Sweeping once more, only the files already being bound
  [3/5] Sealing the chains and the device ledger (the organization adds the signature on receipt)
  [4/5] Precollection check (the organization holds the root key, so it runs the tag recomputation C1)
      Checking without the root key -- the organization runs tag recomputation (C1) …
      FAIL _device.chain.json   records … · {'device_enroll': 1, 'service_start': 3, …}
             - service_start at seq 1 has no matching service_stop -- …   (the reboot in 4-7; without it: OK)
             service intervals 2 · automatic restarts 0 · intervals ended without a stop …
      FAIL delete_<16 hex digits>.chain.json   records … · lines 5
             - source absent: delete.jsonl -- a bound log has disappeared
      OK   denyread_<16 hex digits>.chain.json  records … · lines 6
      OK   first_<16 hex digits>.chain.json     records … · lines 3
      OK   normal_<16 hex digits>.chain.json    records … · lines 20
      FAIL tamper_<16 hex digits>.chain.json    records … · lines 10
             - content mismatch at seq 1
      …
      5 session chains + device ledger · chains with findings: 3   (2 without the reboot in 4-7)
  [5/5] Packing one archive
      6 chains · 4 session logs
    Created file: C:\SIDE_install\employee\collections\SIDE_collection_<device>_<time>.zip
  ```
  6 chains = 5 sessions + 1 ledger. 4 session logs = all except the deleted `delete.jsonl`. ☐
- If the screen shows a forced stop instead of a **normal stop**, send that screen.

**6-4. Status after collection**
- Where: double click `3_status.bat` → *Yes*
- What should appear: no scheduled task · service processes 0 (stopped) · the ledger shows "sealed" ☐

**6-5. Send the collection zip to the organization side**
- Where: admin PowerShell
- Type: `Copy-Item C:\SIDE_install\employee\collections\SIDE_collection_*.zip C:\SIDE_org_side\`

---

## 7. Organization: receive the collection and disclose / 조직: 수신과 제출 (administrator as the organization, 10 min)

> Who: **administrator (as the organization)** · Where: `C:\SIDE_org_side\organization\` (no administrator rights needed)

**7-1. Receive the collection: manifest check · certificate check · seal signature · verification**
- Where: **double click** `C:\SIDE_org_side\organization\2_receive_collection.bat` (bat plain)
- Answer the two questions by dragging from Explorer and pressing Enter:
  1. the received `SIDE_collection_*.zip` ← `C:\SIDE_org_side\SIDE_collection_<device>_<time>.zip`
  2. the organization custody folder of that device (`SIDE_custody_*`) ← the folder
     `C:\SIDE_org_side\SIDE_custody_<device>_<time>`
  (The bat file finds the seal private key in `org_keys\seal_secret.hex` by itself and does not ask for it.)
- What should appear, with content like:
  ```
  [1/4] Extracting and comparing with the manifest
      N files · 0 differ from the manifest
  [2/4] Comparing the enrollment certificate with the organization custody copy
      enrollment certificate match · seal public key match
  [3/4] Adding the organization seal signature
      signed <chain> … (one line per chain)
  [4/4] Verifying with the root key and the seal public key (C1-C4)
      … the same results per chain as in 6-3 [4/5] (delete: source absent · tamper: content mismatch at seq 1) …
      enrollment certificate · device <device> · issued <time>
        root key commitment match
        bound in the first ledger record yes
      seal signature · public key given
        <chain> … valid   (one line per chain, six in all)
      5 session chains + device ledger · chains with findings: 3   (2 without the reboot in 4-7)
    Received into       : C:\SIDE_org_side\organization\received\SIDE_collection_<device>_<time>
    Verification result : findings present, see verification_result.txt  (…)
  ```
  **The findings are correct**, because 5-15 and 5-16 edited and deleted files on purpose. Among the session
  chains, signals must appear **only on the tamper and delete chains**. The ledger also counts as a chain
  with findings when the reboot in 4-7 left an interval without a stop record. ☐

**7-2. Read the verification result**
- Where: Explorer → `C:\SIDE_org_side\organization\received\SIDE_collection_<device>_<time>\verification_result.txt` (Notepad)
- Check:
  - tamper chain: `content mismatch at seq 1` (C3 line hash check: the first line edited in 5-15) ☐
  - delete chain: `source absent: delete.jsonl` ☐
  - first · normal · denyread chains: OK, no signals ☐
  - ledger: 2 service intervals (install · reboot). One interval ended without a stop can appear because of the reboot ☐
  - **no line about a service interval read "without the backup privilege"** ☐

**7-3. Make the disclosure package**
- Where: double click `C:\SIDE_org_side\organization\3_disclose.bat`
- Screens and input:
  1. `[1/3] Which chain to draw from`: a list of chains appears. Write down the records and
     lines of each row.
     - check that the **denyread chain has 6 lines** ☐ (3 means the read deny in 5-17 worked. Send that screen.)
     - at the number prompt, type **the number of the normal chain** Enter
  2. `[2/3] Which records to disclose -- <chain>`: a table of records appears. At the prompt for the numbers to
     disclose, type `1-5` Enter
  3. at the selection rule prompt, type `field test normal session` Enter
- What should appear, with content like:
  ```
  [3/3] Building -- 5 disclosed (total N)
      …
      gap report · ledger records M (total K) · …
    Send only this file.
      C:\SIDE_org_side\organization\disclosures\SIDE_disclosure_<device>_<time>.json
  ```
  ☐

**7-4. Verify before sending (optional)**
- Where: double click `C:\SIDE_org_side\organization\4_verify_package.bat`. It runs
  `verifier\2_check_package.bat` with the organization's `seal_pub.hex`, so it shows what the verifier will see.
  At the prompt for the disclosure package (`SIDE_disclosure_*.json`) drag in the file from 7-3 and press Enter
- What should appear: `seal signature valid` · `verdict: pass` ☐

---

## 8. Verifier: the viewer / 검증자: 검증 창 (administrator as the verifier, 10 min)

> Who: **administrator (as the verifier)** · Where: double click `C:\SIDE_org_side\verifier\1_viewer.bat` → the
> "SIDE viewer (read only)" window
> Without a window, `C:\SIDE_org_side\verifier\2_check_package.bat` checks a package in a command window
> (it asks for the package and the seal public key).

**8-1. Enter the seal public key (a value received through a channel separate from the package)**
- Where: in the middle of the viewer, on the **"Seal public key (seal_pub.hex), received separately from the organization"** row, click
  **[Choose file…]** → `C:\SIDE_org_side\organization\seal_pub.hex`. The field fills with 64 digits and
  `← seal_pub.hex` appears next to it. Pasting the copied value also works.
- Check that **"Reject if unsigned"** is ticked ☐

**8-2. Package view: it must be accepted**
- What to do: **[Package view  (disclosure package)]** → `C:\SIDE_org_side\organization\disclosures\SIDE_disclosure_…json`
- What should appear: layer 1 membership · layer 2 record count · layer 3 seal authenticity (seal root ·
  organization signature) are all green. Under "gap report and scope", the gap report holds, with the
  number of service intervals and the selection rule "field test normal session". At the bottom:
  **"accept: all three layers and the gap report pass"** ☐

**8-3. A different public key must be rejected**
- What to do: change the last character of the public key field to another hex digit, then open the same
  file again with **[Clear] → [Package view]**
- What should appear: **"reject: a layer disagrees"** (the signature layer is red) ☐ → restore the
  original value in the field

**8-4. An edited package must be rejected**
- What to do: in admin PowerShell, make a copy and change one character
  ```powershell
  $p = (Get-ChildItem C:\SIDE_org_side\organization\disclosures\SIDE_disclosure_*.json)[0].FullName
  $t = Get-Content $p -Raw -Encoding UTF8
  $i = $t.IndexOf('"merkle_root"'); $j = $t.IndexOf('"', $i + 14) + 1
  $c = if ($t[$j] -eq 'a') { 'b' } else { 'a' }
  [IO.File]::WriteAllText(($p -replace '\.json$', '_tampered.json'), $t.Substring(0, $j) + $c + $t.Substring($j + 1), (New-Object Text.UTF8Encoding $false))
  ```
  viewer → [Clear] → [Package view] → `…_tampered.json`
- What should appear: **rejected** ☐
  (The copy has the first character of the `"merkle_root"` value changed, which the organization's seal
  signature covers. Changing only the seal's `"tag"` is still accepted by design: the signature covers the
  seal body, and the tag needs the device key. If you edit with Notepad, save with the encoding *UTF-8*
  without BOM.)

**8-5. Chain view: the whole collection**
- What to do: [Clear] → **[Chain view  (collected service folder)]** → the folder
  `C:\SIDE_org_side\organization\received\SIDE_collection_<device>_<time>` → in the root key window that
  follows, `C:\SIDE_org_side\SIDE_custody_<device>_<time>\k0.hex`
- What should appear: enrollment certificate commitment match · service intervals of the device ledger ·
  **signals only on tamper and delete** in the session chain table · the verdict says that 2 of the 5
  session chains have signals that indicate forgery ☐

---

## 9. Cleanup / 정리 (administrator, 5 min)

> Who: **administrator** · Where: administrator account

| # | Where | What to do |
|---|---|---|
| 9-1 | double click `C:\SIDE_install\employee\9_uninstall.bat` → *Yes* | it reports that no SIDE service is running (collection already stopped it) |
| 9-2 | admin PowerShell | `schtasks /Query /TN SIDE` → must print an error such as "ERROR: The system cannot find the file specified." |
| 9-3 | admin PowerShell | first set aside what you will send (below), then `Remove-Item -Recurse -Force C:\ProgramData\SIDE, C:\ProgramData\SIDE_previous_install_* -ErrorAction SilentlyContinue` |
| 9-4 | admin PowerShell | `Remove-Item -Recurse -Force C:\SIDE_install, C:\SIDE_org_side` (this also deletes the test seal private key and root key) |
| 9-5 | Settings → Accounts → Other users → *SIDE test employee* → Remove → "Delete account and data" | deletes the test account and `C:\Users\sidetest` |
| 9-6 | (optional) Settings → Apps → remove Python 3.13 | — |

---

## 10. What to send / 보낼 것

Collect these before 9-3 and 9-4. **Do not send the collection zip that includes the session logs, or
`received\…\sessions\`.** Even in a test they can contain conversation text.

1. the numbers of the ☐ items that did not match, with their screens (copied as they are)
2. `C:\SIDE_org_side\attack_result.txt` (5-2 to 5-17)
3. the full collection screen from 6-3
4. `C:\SIDE_org_side\organization\received\…\verification_result.txt`
5. the chain list from 7-3 (records and lines, especially the lines of denyread)
6. the output of `Get-Content C:\ProgramData\SIDE\restart.log, C:\ProgramData\SIDE\install.json -ErrorAction SilentlyContinue` in admin PowerShell

## 11. When you get stuck / 막혔을 때

| When | What appeared | Cause and what to do |
|---|---|---|
| 3-4 | Python lives under a user folder | Check that you used the Program Files path from 3-3. Repeat 1-4 |
| 3-4 | This Python comes from the Microsoft Store | Repeat 1-3 with the python.org installer |
| 3-4 | The organization seal public key is missing | 3-2 |
| 3-4 | Could not find the profile folder of account 'sidetest' | 2-2 (log in once as the employee) |
| 3-4 | The SIDE service is already running | A previous test is still present → double click `employee\9_uninstall.bat` → *Yes*, then repeat |
| 3-4 | Enrollment did not finish within 60 seconds | Send the output of `Get-Content C:\ProgramData\SIDE\org\enroll.log, C:\ProgramData\SIDE\whoami.txt` from admin PowerShell |
| 4-1 | service processes 0 (stopped) | Run `Get-Content C:\ProgramData\SIDE\restart.log`. An `exit=` value can mean the service failed to enable the backup privilege. Send that content |
| 4-1 | 0 session chains | In admin PowerShell, check that `first.jsonl` from 2-3 is in `C:\Users\sidetest\.claude\projects\side-test\` |
| 5-2 to 5-14 | success instead of access denied | Check with the last line of 1-2 whether `sidetest` is in Administrators. If it is not, send that screen right away (important) |
| 6-3 | forced stop | The service did not finish its sweep within 15 minutes. Send the screen and restart.log |
| 7-1 | enrollment certificate mismatch | Check whether you gave the custody folder of another device |
| 7-1 | This archive was already received | Move that folder under `received\` elsewhere, then repeat |
| bat | Could not find Python 3.10 or later | 1-3 missed *Use admin privileges when installing py.exe* → run the installer again and add the py launcher with *Modify* |
