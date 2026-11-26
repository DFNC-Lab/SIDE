# SIDE guide

This guide lists every option of SIDE and explains how the reference implementation maps to the paper. For
everyday use, the numbered `.bat` files described in the [README](../README.md) and in each role folder are
enough. The `.bat` files run `side.py`, which calls the modules in `src\`.

이 안내서는 SIDE의 모든 옵션을 정리하고 참조 구현이 논문과 어떻게 대응하는지 설명합니다. 평소에는
[README](../README.md)와 각 역할 폴더에 적힌 번호 붙은 `.bat` 파일로 충분합니다. `.bat` 파일은 `side.py`를
실행하고, `side.py`가 `src\`의 모듈을 부릅니다.

---

## 1. Roles and folders / 역할과 폴더

| Role | Who and where | Folder | 누가, 어디서 |
|------|---------------|--------|-------------|
| Employee | Owns the session logs and runs no SIDE tool | — | 세션 로그의 주인이며 SIDE 도구를 실행하지 않음 |
| Organization (IT staff) | On the employee PC, with administrator rights: install, move K0, status, collect, uninstall | `employee\` ([README](../employee/README.md)) | 직원 PC에서 관리자 권한으로 설치·K0 이동·상태·수거·제거 |
| Organization (security staff) | On an organization PC: seal key pair, receive, disclose, preview | `organization\` ([README](../organization/README.md)) | 조직 PC에서 봉인 키 쌍·수거본 받기·제출·미리 보기 |
| Verifier | Anywhere: check a disclosure package | `verifier\` ([README](../verifier/README.md)) | 어디서나 제출 패키지 검증 |

```
Phase 0 · Enrollment / 가입
  organization\1_make_seal_key   → seal_pub.hex to employee\ (private key stays)
  employee\1_install             → SYSTEM task 'SIDE', enrollment, K0 → SIDE_custody_* off the PC
Phase 1 · Binding at creation time / 생성 시점 묶기
  service                        → binds new complete lines at every sweep (2 s)
Phase 2 · Sealing, disclosure, and verification / 봉인·제출·검증
  employee\4_collect             → stop, seal without signature, SIDE_collection_*.zip
  organization\2_receive         → compare certificate, sign the seal, verify C1–C4 with K0
  organization\3_disclose        → SIDE_disclosure_*.json (+ .lines.jsonl)
  verifier\1_viewer or 2_check   → layers 1–3 and gap report → accept / reject
```

Every `.bat` file ends with `Done.` (exit code 0) or `Finished with exit code N`. The employee files reopen
themselves as administrator through User Account Control.

모든 `.bat` 파일은 `Done.`(종료 코드 0) 또는 `Finished with exit code N`으로 끝납니다. 직원 PC 파일은 사용자
계정 컨트롤을 거쳐 관리자 권한으로 스스로 다시 열립니다.

---

## 2. Mapping to the paper / 논문과의 대응

| Paper | In this repository | 이 저장소에서 |
|-------|--------------------|--------------|
| The service runs under the system account; the employee controls neither its folder nor its lifetime | A SYSTEM scheduled task `SIDE` starts at boot, keeps running on battery, has no time limit, and runs at priority 4 (normal). SYSTEM creates `%ProgramData%\SIDE\store` and locks it to SYSTEM and Administrators. The stop file lives in the locked `org\` folder. | SYSTEM 예약 작업 `SIDE`가 부팅 때 시작하고, 배터리에서도 돌며, 시간 제한 없이 우선순위 4(보통)로 돕니다. SYSTEM이 `%ProgramData%\SIDE\store`를 만들어 SYSTEM과 Administrators에게만 엽니다. 정지 파일은 잠긴 `org\` 폴더에 있습니다. |
| The organization makes the seal key pair off the device; the seal private key never enters it | `organization\1_make_seal_key.bat` runs on the organization PC. The device enrolls with the public key only (`--seal-pubkey`). | `organization\1_make_seal_key.bat`는 조직 PC에서 돕니다. 단말은 공개 키만으로 가입합니다(`--seal-pubkey`). |
| The device makes root key K0; until K0 leaves, anyone who copies it can recompute every tag (E3) | Right after enrollment, `employee install` (or `root-key`) moves K0 into `SIDE_custody_*`, checks it against the commitment in the enrollment certificate, then overwrites and deletes the device copy. | 가입 직후 `employee install`(또는 `root-key`)이 K0를 `SIDE_custody_*`로 옮기고, 가입 증서의 약정값과 대조한 뒤 단말 사본을 덮어쓰고 지웁니다. |
| The device seals without a signature; the organization signs the seal at collection | `employee collect` seals without a signature. `organization receive` adds the signature and leaves the seal body and tag unchanged. | `employee collect`는 서명 없이 봉인합니다. `organization receive`가 서명을 더하며 봉인 본문과 태그는 그대로 둡니다. |
| The service reads with the backup privilege; share-deny can still block a read, and the ledger records it (E2) | The installed service always runs with `--read-mode backup`. Each failed read becomes a `sweep_error` record. | 설치된 서비스는 항상 `--read-mode backup`으로 돕니다. 읽기 실패마다 `sweep_error` 레코드가 남습니다. |
| The service restarts after an exception, and the ledger records the stopped interval | `--restart-on-error 5` inside the process, a restart loop in `watch.cmd` (about 10 s apart, up to 1000), and the task's own restart (1 min apart, up to 999). | 프로세스 안의 `--restart-on-error 5`, `watch.cmd`의 재시작 반복(약 10초 간격, 최대 1000회), 예약 작업 자체의 재시작(1분 간격, 최대 999회). |
| Session chain record types (Table 2): session start, line, checkpoint, hook hint, cursor reset | `kind` values `session_start`, `line`, `checkpoint`, `hook_report`, `cursor_reset`. The paper's *hook hint* is `hook_report` in the records; the name stays so existing chains keep verifying. | `kind` 값 `session_start`, `line`, `checkpoint`, `hook_report`, `cursor_reset`. 논문의 *hook hint*는 레코드에서 `hook_report`입니다. 기존 체인이 계속 검증되도록 이름을 유지합니다. |
| Sweep interval; unobserved window (E1) | `--interval 2` (2 s in this implementation). A line changed before the next sweep binds it is not detected. | `--interval 2`. 다음 훑기가 묶기 전에 바뀐 행은 탐지하지 못합니다. |
| Checks C1–C4 | `side_service.py --verify`, the organization's `receive`, and the viewer's chain view. C1 needs K0; C3 and C4 need the session logs. | `side_service.py --verify`, 조직의 `receive`, 검증 창의 체인 보기. C1은 K0가, C3·C4는 세션 로그가 필요합니다. |
| Verifier layers 1–3: inclusion, record count, seal signature | `verifier check` (= `organization verify-package`, = `side_service.py --verify-package`) and the viewer's package view. | `verifier check`(= `organization verify-package`, = `side_service.py --verify-package`)와 검증 창의 패키지 보기. |

---

## 3. side.py options / side.py 옵션

Run from the repository folder: `python side.py <role> <command> [options]`. The employee commands need
administrator rights and run on Windows only.

저장소 폴더에서 `python side.py <역할> <명령> [옵션]`으로 실행합니다. 직원 명령은 관리자 권한이 필요하며
Windows에서만 돕니다.

### employee

| Command and option | Meaning | 의미 |
|--------------------|---------|------|
| `install` | Copies the service code to `%ProgramData%\SIDE\bin`, registers and starts the task, waits for enrollment, then moves K0. Refuses while the service runs. Needs `employee\seal_pub.hex`. | 서비스 코드를 `%ProgramData%\SIDE\bin`에 복사하고 작업을 등록·시작한 뒤 가입을 기다려 K0를 옮깁니다. 서비스가 도는 중이면 거부합니다. `employee\seal_pub.hex`가 필요합니다. |
| `install --employee <account>` | Account whose session logs are bound (default: the signed-in account). Its profile must exist. | 세션 로그를 묶을 계정(기본값: 로그인한 계정). 그 계정의 프로필이 있어야 합니다. |
| `install --key-out <folder>` | Moves K0 there without asking. | 묻지 않고 K0를 그곳으로 옮깁니다. |
| `install --fresh` | Moves an unsealed previous service folder aside and enrolls anew. Without it, install continues in an unsealed folder. | 봉인되지 않은 이전 서비스 폴더를 옆으로 옮기고 새로 가입합니다. 없으면 봉인되지 않은 폴더에서 이어 묶습니다. |
| `root-key [--key-out <folder>]` | Moves K0 off the device if install did not. Asks for the folder when the option is missing. | 설치가 옮기지 않았다면 K0를 단말 밖으로 옮깁니다. 옵션이 없으면 폴더를 묻습니다. |
| `status` | Task, service processes, install record, ledger, number of session chains, K0 copy, restarts. | 작업, 서비스 프로세스, 설치 기록, 기록부, 세션 체인 수, K0 사본, 재시작. |
| `collect` | Stops the service with the stop file and deletes the task, sweeps once more (files already bound only), seals, runs the precollection check (C2–C4), and writes the zip. | 정지 파일로 서비스를 멈추고 작업을 지운 뒤, 한 번 더 훑고(이미 묶던 파일만), 봉인하고, 수거 전 확인(C2–C4)을 하고 zip을 만듭니다. |
| `collect --include-logs` | Also packs the bound session logs (conversation text) under `sessions\`. | 묶인 세션 로그(대화 원문)도 `sessions\`에 넣습니다. |
| `collect --out <folder>` | Folder for the zip (default: `employee\collections\`). | zip을 둘 폴더(기본값: `employee\collections\`). |
| `uninstall` | Stops the service normally and deletes the task. The service folder stays. | 서비스를 정상 정지하고 작업을 지웁니다. 서비스 폴더는 남습니다. |

### organization

| Command and option | Meaning | 의미 |
|--------------------|---------|------|
| `seal-key [--dir <folder>]` | Makes `seal_secret.hex` and `seal_pub.hex` (default folder: `organization\org_keys\`) and copies `seal_pub.hex` to `organization\`. Never overwrites an existing pair. | `seal_secret.hex`와 `seal_pub.hex`를 만들고(기본 폴더: `organization\org_keys\`) `seal_pub.hex`를 `organization\`에 복사합니다. 있는 키 쌍은 덮어쓰지 않습니다. |
| `receive <zip> --custody <dir> --seal-private-key <file>` | Extracts into `received\<zip name>\`, compares with the manifest, compares the certificate and public key with the custody copy, signs, and verifies with `--require-sig`. Stops on any mismatch. Refuses a zip already received. | `received\<zip 이름>\`에 풀고, 매니페스트와 대조하고, 증서와 공개 키를 보관본과 비교한 뒤 서명하고 `--require-sig`로 검증합니다. 어긋나면 멈춥니다. 이미 받은 zip은 거부합니다. |
| `disclose` | Interactive: choose a chain, record numbers, and a selection rule. Writes `disclosures\SIDE_disclosure_<device>_<time>.json`. | 대화식으로 체인, 레코드 번호, 선택 규칙을 고릅니다. `disclosures\SIDE_disclosure_<단말>_<시각>.json`을 만듭니다. |
| `disclose --collection <folder>` | Collection under `received\` (default: the most recent). | `received\` 아래 수거본(기본값: 가장 최근). |
| `disclose --list` | Only lists the chains and their first records. | 체인과 앞쪽 레코드만 보여 줍니다. |
| `disclose --chain N` | Chain by number (from the list) or by file name. | 목록 번호나 파일 이름으로 체인을 고릅니다. |
| `disclose --range 5-9,12` | Record numbers to disclose, from 0. | 제출할 레코드 번호(0부터). |
| `disclose --rule <text>` | Selection rule written into the scope statement. | 범위 진술에 적을 선택 규칙. |
| `disclose --lines` | Also writes the text of the chosen lines to `.lines.jsonl`. Needs a collection with session logs. | 고른 행의 원문을 `.lines.jsonl`에도 씁니다. 세션 로그가 든 수거본이 필요합니다. |
| `verify-package <package> --seal-public-key <key> [--lines <file>]` | Same as `verifier check`. | `verifier check`와 같습니다. |

### verifier

| Command and option | Meaning | 의미 |
|--------------------|---------|------|
| (none) | Opens the viewer window. Needs tkinter. | 검증 창을 엽니다. tkinter가 필요합니다. |
| `check <package>` | Verifies layers 1–3 and the gap report and prints `verdict: pass` or `verdict: reject` (exit code 0 or 1). Always requires a seal signature. | 1–3계층과 공백 보고를 검증해 `verdict: pass` 또는 `verdict: reject`(종료 코드 0 또는 1)를 출력합니다. 봉인 서명을 항상 요구합니다. |
| `--seal-public-key <key>` | Required. A file under any name, or the 64-digit value. | 필수. 이름이 무엇이든 파일, 또는 64자리 값. |
| `--lines <file>` | Compares the byte range and SHA-256 of each disclosed line. `verifier\2_check_package.bat` finds a same-name `.lines.jsonl` by itself; this command does not. | 제출된 행마다 바이트 범위와 SHA-256을 대조합니다. `verifier\2_check_package.bat`는 같은 이름의 `.lines.jsonl`을 스스로 찾지만 이 명령은 찾지 않습니다. |

---

## 4. side_service.py options / side_service.py 옵션

`src\side_service.py` is the binding service and verifier that every tool calls. The environment variable
`SIDE_STORE` names the service folder; without it the folder is `src\.side_store` (testing only).

`src\side_service.py`는 모든 도구가 부르는 묶기 서비스이자 검증기입니다. 환경 변수 `SIDE_STORE`가 서비스
폴더를 가리키며, 없으면 `src\.side_store`를 씁니다(시험용).

| Option | Meaning | 의미 |
|--------|---------|------|
| `--once` · `--watch` | Sweep once, or run resident. | 한 번 훑기, 또는 상주 실행. |
| `--source claude codex antigravity bound` | What to sweep by name. `bound` continues only with files already bound. | 이름으로 훑을 대상. `bound`는 이미 묶던 파일만 이어 갑니다. |
| `--patterns <glob> …` | Paths to sweep, given directly. | 훑을 경로를 직접 지정. |
| `--interval <s>` | Sweep interval (default 2). | 훑기 간격(기본값 2). |
| `--checkpoint-sec <s>` · `--heartbeat-sec <s>` | Checkpoint interval for a changed file (default 30) and an unchanged one (default 300). | 바뀐 파일(기본값 30)과 바뀌지 않은 파일(기본값 300)의 체크포인트 간격. |
| `--stopfile <file>` | With `--watch`: stop normally when this file appears. | `--watch`와 함께: 이 파일이 생기면 정상 정지. |
| `--restart-on-error N` | With `--watch`: after an exception, record a stop and a restart and start again, up to N in a row (default 0). | `--watch`와 함께: 예외 뒤 정지와 재시작을 기록하고 다시 시작, 연속 N회까지(기본값 0). |
| `--read-mode auto\|backup\|plain` | Read path. `backup` refuses to start without the backup privilege; `auto` (default) falls back to a plain open. | 읽기 경로. `backup`은 백업 권한이 없으면 시작을 거부하고, `auto`(기본값)는 일반 열기로 물러납니다. |
| `--hints-dir <dir>` | Hook hint drop folder (default `hints\` in the service folder). Hints become untrusted `hook_report` records. | 훅 힌트 폴더(기본값: 서비스 폴더의 `hints\`). 힌트는 신뢰하지 않는 `hook_report` 레코드가 됩니다. |
| `--enroll --seal-pubkey <key> [--org-out <file>]` | Enroll once. `--org-out` writes K0 to a file outside the service folder instead of the screen. | 한 번 가입. `--org-out`은 K0를 화면 대신 서비스 폴더 밖 파일에 씁니다. |
| `--gen-seal-keypair <dir>` | Organization side: make the seal key pair outside the service folder. | 조직 쪽: 서비스 폴더 밖에 봉인 키 쌍을 만듭니다. |
| `--seal [--force-seal]` | Seal the chains, then the ledger. Refuses while the ledger has a `service_start` without a stop, unless `--force-seal`. One broken chain does not stop the others. | 체인을 봉인하고 마지막에 기록부를 봉인합니다. 기록부에 정지 없는 `service_start`가 있으면 `--force-seal` 없이는 거부합니다. 깨진 체인 하나가 나머지를 막지 않습니다. |
| `--countersign --seal-secret <key>` | Organization side: sign sealed chains. Refuses a key that does not match the enrolled public key. | 조직 쪽: 봉인된 체인에 서명. 가입된 공개 키와 맞지 않는 키는 거부합니다. |
| `--verify` | Verify the ledger and every chain (C2–C4; C1 and the commitment with `--org-key`). | 기록부와 모든 체인 검증(C2–C4, `--org-key`가 있으면 C1과 약정값). |
| `--org-key <key>` | K0 for `--verify`: file or 64 hex digits. | `--verify`용 K0: 파일 또는 16진 64자리. |
| `--seal-pub <key\|store>` | Public key for seal signatures. `store` uses the device copy, which is no basis of trust. | 봉인 서명용 공개 키. `store`는 단말 사본을 쓰며 신뢰 근거가 아닙니다. |
| `--require-sig` | With `--verify` or `--disclose`: count a seal without a signature as a finding. | `--verify`나 `--disclose`와 함께: 서명 없는 봉인을 발견 사항으로 셉니다. |
| `--sessions-dir <dir>` | With `--verify` or `--disclose --with-lines`: session log folder of a collection (`sessions\`). | `--verify`나 `--disclose --with-lines`와 함께: 수거본의 세션 로그 폴더(`sessions\`). |
| `--skip-source` | With `--verify`: no session logs; skips C3 and C4 and reports how many chains skipped them. | `--verify`와 함께: 세션 로그 없음. C3·C4를 건너뛰고 건너뛴 체인 수를 알립니다. |
| `--disclose <chain> --seqs 3,5,7` | Build a package from one chain, with a gap report and a scope statement. | 체인 하나로 공백 보고와 범위 진술이 든 패키지를 만듭니다. |
| `--scope <text>` · `--with-lines` | With `--disclose`: selection rule; also write `.lines.jsonl`. | `--disclose`와 함께: 선택 규칙, `.lines.jsonl`도 쓰기. |
| `--verify-package <file> [--lines <file>]` | Verify a received package. Always requires a seal signature. | 받은 패키지 검증. 봉인 서명을 항상 요구합니다. |
| `--require-gaps` | With `--verify-package`: reject a package without a gap report. | `--verify-package`와 함께: 공백 보고 없는 패키지를 거부. |

For example, the chain view without a window:
예를 들어 창 없이 체인 보기와 같은 검증을 하려면:

```
set SIDE_STORE=organization\received\<zip name>
python src\side_service.py --verify --org-key <k0.hex> --seal-pub <seal_pub.hex> --require-sig --sessions-dir organization\received\<zip name>\sessions
```

---

## 5. Reference implementation / 참조 구현

| Topic | Detail | 세부 |
|-------|--------|------|
| Revision | Every `service_start` record carries `REVISION` from `src\side_core.py`. Install refuses a copied core with another revision. | 모든 `service_start` 레코드에 `src\side_core.py`의 `REVISION`이 들어갑니다. 설치는 다른 리비전의 코어를 거부합니다. |
| Core | `src\side_core.py` provides `leaf_hash`, `merkle_root`, and `KeySchedule`. Service and verifier use them unchanged. | `src\side_core.py`가 `leaf_hash`, `merkle_root`, `KeySchedule`을 제공하며 서비스와 검증기가 그대로 씁니다. |
| Install hardening | Python runs with `-I` (no environment variables, no user site-packages) from `%ProgramData%\SIDE\bin`, which only SYSTEM and Administrators can write. `install.json` records the SHA-256 of each module. | Python은 `-I`(환경 변수·사용자 site-packages 무시)로 SYSTEM과 Administrators만 쓸 수 있는 `%ProgramData%\SIDE\bin`에서 돕니다. `install.json`에 모듈별 SHA-256이 남습니다. |
| Sealing | The verifier checks the seal body against the chain: record count, Merkle root, and last tag without a key, and the seal tag K_N with the key schedule from K0. Removing the last records of a sealed chain is detected. Nothing is appended to a sealed chain or ledger. | 검증기는 봉인 본문을 체인과 대조합니다. 레코드 수, 머클 루트, 마지막 태그는 키 없이, 봉인 태그 K_N은 K0에서 이어진 키로 확인합니다. 봉인된 체인의 끝 레코드를 지우면 탐지됩니다. 봉인된 체인과 기록부에는 더 붙이지 않습니다. |
| Stop | Tools stop the service with the stop file, so the ledger gets a `service_stop`. They kill only when the stop file has no effect, and the ledger then shows an abnormal stop. | 도구는 정지 파일로 서비스를 멈춰 기록부에 `service_stop`이 남습니다. 정지 파일이 듣지 않을 때만 강제 종료하며, 이때 기록부에는 비정상 정지가 남습니다. |
| Ledger | Records the agent name (`claude-code`, `codex-cli`, `antigravity`, `antigravity-cli`) at session start and open. A duplicate session open is visible without K0. A first observation writes `session_seen` and `session_open`. | 세션 시작과 열기에 에이전트 이름(`claude-code`, `codex-cli`, `antigravity`, `antigravity-cli`)을 남깁니다. 중복 세션 열기는 K0 없이 보입니다. 처음 관측하면 `session_seen`과 `session_open`을 씁니다. |
| Disclosure package | Holds the chosen records, Merkle inclusion proofs, the signed seal, the total count, a gap report (ledger records about the session with proofs against the sealed ledger), and a scope statement (rule, records, period). No conversation text. | 고른 레코드, 머클 포함 증명, 서명된 봉인, 전체 수, 공백 보고(봉인된 기록부에 대한 증명이 붙은 해당 세션의 기록부 레코드), 범위 진술(규칙·레코드·기간)이 들어 있습니다. 대화 원문은 없습니다. |
| Read mode | Verification output and the gap report flag a service interval that ran without the backup privilege, without counting it as a finding. In backup mode a service that cannot enable the privilege refuses to start; the reason goes to `service.log` and the exit code to `restart.log`. | 검증 출력과 공백 보고는 백업 권한 없이 돈 서비스 구간을 표시하되 발견 사항으로 세지 않습니다. backup 모드에서 권한을 켜지 못한 서비스는 시작을 거부하며, 이유는 `service.log`, 종료 코드는 `restart.log`에 남습니다. |
| Blank lines | Not bound. A gap of whitespace only between two lines is not a C2 offset gap when the session log is present. | 묶지 않습니다. 세션 로그가 있으면 두 행 사이의 공백 문자만 있는 틈은 C2 오프셋 틈으로 보지 않습니다. |
| Durability | State, chains, key files, and the ledger are flushed (fsync) before they are swapped in. The used stage key is overwritten with zeros in memory (best effort in CPython). | 상태, 체인, 키 파일, 기록부는 교체 전에 디스크에 기록(fsync)합니다. 쓴 단계 키는 메모리에서 0으로 덮어씁니다(CPython에서는 최선 노력). |
| Key file names | `seal_pub.hex` everywhere. The tools also read the legacy name `seal_pub.key` and accept a file with a BOM. The viewer and `verifier check` accept a public key file under any name. | 어디서나 `seal_pub.hex`. 옛 이름 `seal_pub.key`와 BOM이 붙은 파일도 읽습니다. 검증 창과 `verifier check`는 이름이 무엇이든 공개 키 파일을 받습니다. |
| Hooks | SIDE installs no agent hooks. Hints a hook drops into the hints folder are bound as untrusted `hook_report` records. | SIDE는 에이전트 훅을 설치하지 않습니다. 훅이 힌트 폴더에 둔 힌트는 신뢰하지 않는 `hook_report` 레코드로 묶습니다. |

---

## 6. Exposures and known limitations / 노출과 알려진 한계

| Item | Meaning | 의미 |
|------|---------|------|
| E1 unobserved window | A line changed before the next sweep binds it is not detected. The real window is the sweep duration plus the 2 s interval. | 다음 훑기가 묶기 전에 바뀐 행은 탐지하지 못합니다. 실제 구간은 훑기 시간에 2초 간격을 더한 것입니다. |
| E2 original records, read blocking | While the employee holds a session log open with share-deny, the service cannot read it; the ledger records each failed read as `sweep_error`, but not the start and end of the affected interval. SIDE protects the chain, not the session log file. | 직원이 세션 로그를 share-deny로 열어 두면 서비스가 읽지 못합니다. 읽기 실패마다 `sweep_error`가 남지만 영향받은 구간의 시작과 끝은 계산하지 않습니다. SIDE는 체인을 지키며 세션 로그 파일은 지키지 않습니다. |
| E3 key window at enrollment | Anyone who copies K0 before it leaves the PC can recompute every tag. On an SSD the overwrite may not reach the original blocks, so keep BitLocker on. | K0가 PC를 떠나기 전에 복사한 사람은 모든 태그를 다시 계산할 수 있습니다. SSD에서는 덮어쓰기가 원래 블록에 닿지 않을 수 있으니 BitLocker를 켜 둡니다. |
| Boot to service start | About 2 minutes in the field test; a change in this interval is not detected. The ledger shows it as an interval without a stop record. | 현장 시험에서 약 2분. 이 구간의 변경은 탐지하지 못하며, 기록부에는 정지 기록 없는 구간으로 보입니다. |
| Administrator stop | An administrator can stop the service. The ledger records the stopped interval. | 관리자는 서비스를 멈출 수 있습니다. 멈춘 구간은 기록부에 남습니다. |
| Checkpoint interval | The service writes a checkpoint every 30 s for a changed log and every 5 min for an unchanged one, but the verifier does not flag a longer gap between checkpoints. The first pass over many existing logs can take minutes. | 서비스는 바뀐 로그에 30초, 바뀌지 않은 로그에 5분마다 체크포인트를 쓰지만, 검증기는 더 긴 틈을 표시하지 않습니다. 기존 로그가 많으면 첫 묶기에 몇 분이 걸립니다. |
| Package tags | Package verification checks inclusion proofs, the seal root, the record count, and the seal signature. It does not recompute the tags of the disclosed records. | 패키지 검증은 포함 증명, 봉인 루트, 레코드 수, 봉인 서명을 확인하며, 제출 레코드의 태그는 다시 계산하지 않습니다. |
| Gap report | A ledger record that the discloser leaves out of the gap report is invisible to the verifier, which sees only the difference between the total ledger count and the records received. | 제출자가 공백 보고에서 뺀 기록부 레코드는 검증자에게 보이지 않습니다. 검증자는 기록부 전체 수와 받은 레코드 수의 차이만 봅니다. |
| Key file replacement | A key file is replaced by a new file; the old file's location is not overwritten. This order keeps a key available if the service is interrupted. | 키 파일은 새 파일로 교체되며 옛 파일 자리는 덮어쓰지 않습니다. 이 순서 덕분에 서비스가 끊겨도 키가 남습니다. |
| Service type | The service is a SYSTEM scheduled task, not a registered Windows service. | 서비스는 등록된 Windows 서비스가 아니라 SYSTEM 예약 작업입니다. |

A signal alone is not evidence of tampering: agent compaction and service stops raise the same signals,
and a person decides.

신호 하나만으로는 조작의 증거가 아닙니다. 에이전트의 압축과 서비스 정지도 같은 신호를 내며, 판단은 사람이 합니다.

---

## 7. Testing / 시험

| Test | Meaning | 의미 |
|------|---------|------|
| `python tests\test_end_to_end.py` | Runs the whole flow on one PC without administrator rights | 관리자 권한 없이 한 PC에서 전 과정을 돌림 |
| `field-test\` | On a spare Windows PC: install, optional reboot, 13 employee attempts to stop or open the service (each must be denied), content mismatch, deleted session, a log whose read access the employee denied still bound through the backup read, collection, disclosure, verification. See [field-test-manual.md](field-test-manual.md). | 여분 Windows PC에서 설치, 선택적 재부팅, 서비스를 멈추거나 여는 직원 시도 13개(모두 거부돼야 함), 내용 불일치, 삭제된 세션, 직원이 읽기를 거부한 로그도 백업 읽기로 묶이는지, 수거, 제출, 검증. [field-test-manual.md](field-test-manual.md) 참고 |
