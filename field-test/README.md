# SIDE field test

The field test proves on a real Windows PC that the SIDE binding service, running under the SYSTEM
account, survives the attacks of a standard user. One PC plays every role: an administrator account
installs, collects, and acts as the organization and the verifier, and a standard user account plays
the employee. Five `.bat` files run every check and leave one result file. A run takes 15 to 20 minutes.

필드 시험은 SYSTEM 계정에서 도는 SIDE 묶기 서비스가 표준 사용자의 공격을 견디는지 실제 Windows PC에서
증명합니다. PC 한 대가 모든 역할을 맡습니다. 관리자 계정이 설치·수거를 하고 조직과 검증자 역할을 하며,
표준 사용자 계정이 직원 역할을 합니다. `.bat` 파일 다섯 개가 모든 검사를 하고 결과 파일 하나를 남깁니다.
한 번 도는 데 15~20분 걸립니다.

> **Never run the field test on a work PC.** It installs a SYSTEM service, attacks it, and deletes
> `C:\ProgramData\SIDE` at cleanup. Use a spare test PC with administrator rights.
> **업무용 PC에서는 절대 돌리지 마십시오.** SYSTEM 서비스를 설치해 공격하고, 정리할 때
> `C:\ProgramData\SIDE`를 지웁니다. 관리자 권한이 있는 여분의 시험용 PC를 쓰십시오.

---

## 1. Before you start / 준비

1. Put the whole repository where the administrator account can reach it, for example the desktop.
   `1_admin_install.bat` copies `employee\`, `organization\`, `verifier\` and `src\` from it.
   저장소 전체를 관리자 계정이 쓰는 곳(예: 바탕 화면)에 둡니다. `1_admin_install.bat`이 거기서
   `employee\`, `organization\`, `verifier\`, `src\`를 복사합니다.
2. Create a standard user account for the employee and sign in to it at least once.
   An administrator account cannot play the employee, because an administrator can stop the service.
   직원용 표준 사용자 계정을 만들고 한 번 이상 로그인해 둡니다. 관리자는 서비스를 멈출 수 있으므로
   관리자 계정은 직원 역할을 할 수 없습니다.
3. You do not need to install Python. If no Python for all users exists, `1_admin_install.bat` installs
   Python 3.13 for all users with winget.
   Python을 직접 설치할 필요는 없습니다. 모든 사용자용 Python이 없으면 `1_admin_install.bat`이 winget으로
   Python 3.13을 모든 사용자용으로 설치합니다.

The test creates two folders on the system drive and locks both against the employee.
시험은 시스템 드라이브에 두 폴더를 만들고 둘 다 직원이 열지 못하게 잠급니다.

| Folder | Holds | 들어 있는 것 |
|--------|-------|-------------|
| `C:\SIDE_install\` | `employee\` and `src\`: the employee PC bundle, `seal_pub.hex`, collections | `employee\`와 `src\`: 직원 PC 묶음, `seal_pub.hex`, 수거 파일 |
| `C:\SIDE_org_side\` | `organization\`, `verifier\` and `src\`, the seal private key, the root key custody `SIDE_custody_*` | `organization\`, `verifier\`, `src\`, 봉인 개인 키, 루트 키 보관본 `SIDE_custody_*` |
| `C:\Users\Public\SIDE_test\` | `2_employee_test.bat` and `side_test.py` for the employee | 직원이 실행할 `2_employee_test.bat`과 `side_test.py` |

---

## 2. Order / 순서

To switch accounts, press **Win + L → Other user**, or Start → user icon → Sign out.
계정을 바꿀 때는 **Win + L → 다른 사용자**를 누르거나 시작 → 사용자 아이콘 → 로그아웃을 고릅니다.

| Step | Who | Double click | What happens | 하는 일 |
|:---:|-----|--------------|--------------|--------|
| 1 | administrator | `field-test\1_admin_install.bat` | Reopens as administrator ([Yes]). Pick the employee account number (Enter = 1). Installs and checks the deployment. | 관리자로 다시 엽니다([예]). 직원 계정 번호를 고릅니다(Enter = 1). 설치하고 배포를 검사합니다. |
| — | administrator | (optional) | Reboot test: restart, sign in as administrator, and run `0_diagnose.bat`. Wait until the "last 20 ledger records" show a `service_start` after the reboot (about 2 minutes). | 재부팅 시험: 재시작 후 관리자로 로그인해 `0_diagnose.bat`을 실행합니다. "last 20 ledger records"에 재부팅 뒤의 `service_start`가 보일 때까지(약 2분) 기다립니다. |
| 2 | employee | `C:\Users\Public\SIDE_test\2_employee_test.bat` | Runs without administrator rights. Writes session logs, edits them, and attacks the service. | 관리자 권한 없이 실행합니다. 세션 로그를 쓰고 고치며 서비스를 공격합니다. |
| 3 | administrator | `field-test\3_admin_collect_and_verify.bat` | Reopens as administrator ([Yes]). Collects, receives as the organization, discloses, and verifies. | 관리자로 다시 엽니다([예]). 수거하고 조직으로 수신·제출한 뒤 검증합니다. |
| 4 | administrator | — | Send `field-test\test_summary_<time>.txt`. | `field-test\test_summary_<time>.txt`를 보냅니다. |
| 9 | administrator | `field-test\9_admin_cleanup.bat` | When everything is done, type `y`. Removes everything the test created and keeps `test_summary_*.txt`. | 모두 끝나면 `y`를 입력합니다. 시험이 만든 것을 모두 지우고 `test_summary_*.txt`는 남깁니다. |

`0_diagnose.bat` writes the current state into `test_diagnosis_<time>.txt` at any time.
`0_diagnose.bat`은 언제든 현재 상태를 `test_diagnosis_<time>.txt`에 씁니다.

---

## 3. What each stage checks / 단계별 검사

Every check is recorded as PASS, FAIL, or INFO. Stage 3 merges stages 1, 2, and 3 into `test_summary_<time>.txt`.
모든 검사는 PASS, FAIL, INFO로 남습니다. 3단계가 1·2·3단계 결과를 `test_summary_<time>.txt`에 합칩니다.

### Stage 1 · Install (Phase 0 Enrollment) / 설치 (0단계 가입)

- Copies the bundles into `C:\SIDE_install` and `C:\SIDE_org_side` and locks both against the employee.
  묶음을 `C:\SIDE_install`과 `C:\SIDE_org_side`에 복사하고 둘 다 직원에게서 잠급니다.
- The organization makes the seal key pair. Only `seal_pub.hex` goes into `employee\`.
  조직이 봉인 키 쌍을 만듭니다. `employee\`에는 `seal_pub.hex`만 들어갑니다.
- Installs the SYSTEM scheduled task, enrolls the PC, and moves the root key K0 to `C:\SIDE_org_side\SIDE_custody_*`.
  SYSTEM 예약 작업을 설치해 PC를 가입시키고, 루트 키 K0를 `C:\SIDE_org_side\SIDE_custody_*`로 옮깁니다.
- 25 checks, among them: one service process · SYSTEM · `--read-mode backup` · employee path on the command line ·
  scheduled task (SYSTEM, at system startup, on battery, no time limit, running, priority 4) · `watch.cmd` writes
  `service.log` · 4 service folders open to SYSTEM and Administrators only · no copy of K0 on the PC · the chains
  bound so far verify · no service interval read without the backup privilege.
  검사 25개. 서비스 프로세스 1개 · SYSTEM · `--read-mode backup` · 명령줄의 직원 경로 · 예약 작업(SYSTEM, 시스템 시작 시,
  배터리, 시간 제한 없음, 실행 중, 우선순위 4) · `watch.cmd`의 `service.log` 기록 · 서비스 폴더 4개는 SYSTEM과
  Administrators만 · PC에 K0 사본 없음 · 지금까지 묶인 체인 검증 · 백업 권한 없이 읽은 서비스 구간 없음 등.

### Stage 2 · Employee (Phase 1 Binding at creation time) / 직원 (1단계 생성 시점 묶기)

- Writes 4 session logs where Claude Code keeps them (`.claude\projects\side-test-<time>\`): normal (20 lines),
  tamper (10), delete (5), denyread (3 + 3), then waits 60 seconds for binding.
  Claude Code가 쓰는 곳(`.claude\projects\side-test-<time>\`)에 세션 로그 4개를 씁니다. normal(20행), tamper(10),
  delete(5), denyread(3 + 3). 그리고 묶일 때까지 60초 기다립니다.
- 3 edits the employee can make to their own logs: change one character (tamper), delete the file (delete),
  deny read to SYSTEM and keep writing (denyread). SIDE cannot block these; collection must reveal them.
  직원이 자기 로그에 할 수 있는 편집 3개. 한 글자 바꾸기(tamper), 파일 지우기(delete), SYSTEM 읽기 거부 후 계속 쓰기
  (denyread). SIDE는 막지 못하며, 수거가 드러내야 합니다.
- 13 attempts to stop or open the service, each passing only if denied: end or delete the scheduled task ·
  kill the process · open the service folder · write the stop file · delete the device ledger · open the key folder ·
  change `watch.cmd` · take ownership · change permissions · read the seal private key · open `C:\SIDE_org_side` ·
  open `C:\SIDE_install`.
  서비스를 멈추거나 여는 시도 13개. 거부될 때만 통과합니다. 예약 작업 종료·삭제 · 프로세스 종료 · 서비스 폴더 열기 ·
  정지 파일 쓰기 · 단말 기록부 삭제 · 키 폴더 열기 · `watch.cmd` 변경 · 소유권 가져오기 · 권한 변경 · 봉인 개인 키 읽기 ·
  `C:\SIDE_org_side` 열기 · `C:\SIDE_install` 열기.

### Stage 3 · Collect and verify (Phase 2 Sealing, disclosure, and verification) / 수거·검증 (2단계 봉인·제출·검증)

- After the attacks: still one SYSTEM service process · no automatic restart · the service was running during
  the employee test · normal has 20 chained lines and denyread all 6 (backup read).
  공격 뒤: SYSTEM 서비스 프로세스 여전히 1개 · 자동 재시작 없음 · 직원 시험 동안 서비스 동작 중 · normal 20행,
  denyread 6행 모두 체인에 묶임(백업 읽기).
- Collection with session logs: normal stop through the stop file, sealing, `SIDE_collection_*.zip`.
  세션 로그를 넣어 수거: 정지 파일로 정상 정지, 봉인, `SIDE_collection_*.zip`.
- Organization receive: manifest · enrollment certificate and seal public key against the custody copy ·
  root key commitment · seal signature · C1–C4 with K0. tamper must show *content mismatch*, delete must show
  *source absent*, and the other session chains must show no signals.
  조직 수신: 매니페스트 · 보관본과 가입 증서·봉인 공개 키 대조 · 루트 키 커밋 · 봉인 서명 · K0로 C1–C4.
  tamper는 *content mismatch*, delete는 *source absent*로 나와야 하고, 다른 세션 체인에는 신호가 없어야 합니다.
- Disclosure package of records 1 to 5 of the normal session, then verification: the correct seal public key
  passes, a wrong key is rejected, and 4 tampered packages are rejected. A package with only `seal.tag` changed
  passes by design (INFO), because the seal signature does not cover that HMAC tag.
  normal 세션의 레코드 1~5로 제출 패키지를 만들고 검증합니다. 맞는 봉인 공개 키는 통과, 틀린 키는 거부, 조작한
  패키지 4개는 거부됩니다. `seal.tag`만 바꾼 패키지는 설계상 통과합니다(INFO). 봉인 서명이 그 HMAC 태그를
  덮지 않기 때문입니다.

---

## 4. If something goes wrong / 문제가 생기면

On an error the window stays open and the test writes `test_diagnosis_<time>.txt` (the screen shows where).
It holds the scheduled task, service processes, install and enrollment records, folder permissions, and the
screen log, but no conversation text. Send that file. The full screen output is also in `test_log_<stage>_<time>.log`.
오류가 나면 창이 열린 채로 남고 `test_diagnosis_<time>.txt`를 씁니다(위치는 화면에 나옵니다). 예약 작업, 서비스
프로세스, 설치·가입 기록, 폴더 권한, 화면 기록이 들어 있고 대화 원문은 없습니다. 그 파일을 보내 주십시오.
화면 출력 전체는 `test_log_<stage>_<time>.log`에도 남습니다.

**Can I just run the same bat file again?**  
Yes. `1` removes what is left and starts over. `3` skips a collection that already finished and continues.  
예. `1`은 남은 것을 지우고 처음부터 시작합니다. `3`은 이미 끝난 수거를 건너뛰고 이어 갑니다.

**User Account Control asks for a password. Why?**  
The current account is not an administrator. Sign in with an administrator account and run 1, 3, and 9.  
지금 계정이 관리자가 아닙니다. 관리자 계정으로 로그인해 1, 3, 9를 실행합니다.

**"The automatic install did not work" appears for Python. What now?**  
On the python.org page that opens, install with *Customize installation → Install Python for all users*, then run `1` again.  
열린 python.org 페이지에서 *Customize installation → Install Python for all users*로 설치한 뒤 `1`을 다시 실행합니다.

**The account list shows "(none)". What now?**  
Create a standard user in Settings → Accounts → Other users, sign in to it once, then run `1` again.  
설정 → 계정 → 다른 사용자에서 표준 사용자를 만들고 한 번 로그인한 뒤 `1`을 다시 실행합니다.

**`2` says "Python 3.10 or later for all users was not found". Why?**  
`1` did not finish. Start again from `1` in the administrator account.  
`1`이 끝나지 않았습니다. 관리자 계정에서 `1`부터 다시 시작합니다.

**`2` says "This window has administrator rights". Why?**  
Start it with a double click from the employee account, not with *Run as administrator*.  
직원 계정에서 *관리자 권한으로 실행*이 아니라 더블 클릭으로 시작합니다.

**`3` says "No employee test result". Why?**  
Run `2` from the employee account first.  
먼저 직원 계정에서 `2`를 실행합니다.

**`3` says "the service came up only after the employee test". Why?**  
The employee test ran after a reboot but before the service started again. Run `1` again, and after a reboot wait for the new `service_start` in `0_diagnose.bat` before running `2`.  
재부팅 뒤 서비스가 다시 시작하기 전에 직원 시험을 돌렸습니다. `1`부터 다시 하고, 재부팅했다면 `0_diagnose.bat`에서 새 `service_start`를 확인한 뒤 `2`를 실행합니다.

**What must I not send?**  
`C:\SIDE_install\employee\collections\*.zip` and `C:\SIDE_org_side\organization\received\`. They may hold the employee account's real AI conversations. The result and diagnosis files hold no conversation text.  
`C:\SIDE_install\employee\collections\*.zip`과 `C:\SIDE_org_side\organization\received\`입니다. 직원 계정의 실제 AI 대화가 들어 있을 수 있습니다. 결과 파일과 진단 파일에는 대화 원문이 없습니다.

The same test done by hand, step by step, is in [docs/field-test-manual.md](../docs/field-test-manual.md).
같은 시험을 손으로 한 단계씩 하는 방법은 [docs/field-test-manual.md](../docs/field-test-manual.md)에 있습니다.
