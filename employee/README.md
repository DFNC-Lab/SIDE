# SIDE employee folder

IT staff of the organization run this folder on the employee PC. The employee runs no SIDE tool and
works as usual. After install, a service under the Windows system account binds every new line the AI
coding agents write, and the employee cannot stop it or open its folder.

조직의 IT 담당이 직원 PC에서 이 폴더를 실행합니다. 직원은 SIDE 도구를 실행하지 않고 평소처럼 일합니다.
설치하면 Windows SYSTEM 계정으로 실행되는 서비스가, AI 코딩 에이전트가 새로 쓰는 행을 묶습니다. 직원은 이
서비스를 멈추거나 그 폴더를 열 수 없습니다.

This folder works on its own. Copy it whole, including `lib\`, to the employee PC.
이 폴더는 따로 동작합니다. `lib\`까지 폴더 전체를 직원 PC에 복사합니다.

---

## 1. Before you start / 준비

| Item | Meaning | 의미 |
|------|---------|------|
| Python | Python 3.10 or later from python.org, installed *for all users*. The install refuses a Python under a user folder or from the Microsoft Store, because its owner could change it. | python.org의 Python 3.10 이상을 *모든 사용자용*으로 설치합니다. 사용자 폴더나 Microsoft Store의 Python은 그 주인이 바꿀 수 있어 설치 단계에서 거부합니다. |
| `seal_pub.hex` | The seal public key from `organization\1_make_seal_key.bat`. Put it in this folder. The seal private key never comes to this PC. | `organization\1_make_seal_key.bat`로 만든 봉인 공개 키. 이 폴더에 넣습니다. 봉인 개인 키는 이 PC로 가져오지 않습니다. |
| USB drive | Receives the root key K0 right after install. The employee must not be able to read it. | 설치 직후 루트 키 K0를 받습니다. 직원이 읽을 수 없어야 합니다. |

---

## 2. Steps / 단계

Every file asks for administrator rights by itself. Click *Yes* in the User Account Control window.
Each file ends with `Done.` or `Finished with exit code N`.

모든 파일은 관리자 권한을 스스로 요청합니다. 사용자 계정 컨트롤 창에서 *예*를 누릅니다.
파일마다 `Done.` 또는 `Finished with exit code N`으로 끝납니다.

| Step | Double click | What happens | 하는 일 |
|:---:|--------------|--------------|--------|
| 1 | `1_install.bat` | Asks for the employee account (Enter = the signed-in account), installs the binding service, and enrolls the PC. It then asks for a USB folder, moves the root key K0 there into `SIDE_custody_<device>_<time>\`, and erases the PC copy. Give that folder to security staff. | 묶을 직원 계정(Enter = 로그인한 계정)을 묻고 서비스를 설치해 PC를 가입시킵니다. 이어 USB 폴더를 물어 루트 키 K0를 `SIDE_custody_<단말>_<시각>\`으로 옮기고 PC 사본을 지웁니다. 그 폴더를 보안 담당에게 넘깁니다. |
| 2 | `2_move_root_key.bat` | Only if step 1 did not move K0. Type the destination folder (for example `E:\`); dragging does not work in an administrator window. Until K0 moves, anyone with administrator rights can copy it and recompute every tag (E3). | 1단계에서 K0를 옮기지 않은 경우에만 실행합니다. 대상 폴더를 입력합니다(예: `E:\`). 관리자 창에는 끌어 놓기가 되지 않습니다. K0가 옮겨지기 전에는 관리자 권한이 있는 누구나 복사해 모든 태그를 다시 계산할 수 있습니다(E3). |
| 3 | `3_status.bat` | Shows the scheduled task, the number of service processes (1 is normal), the device ledger, the number of session chains, whether K0 is still on the PC, and the restart count. | 예약 작업, 서비스 프로세스 수(1이 정상), 단말 기록부, 세션 체인 수, K0가 PC에 남았는지, 재시작 횟수를 보여 줍니다. |
| 4 | `4_collect.bat` | After an incident. Stops the service, sweeps once more, seals the chains and the ledger without a signature, checks C2–C4, and writes `collections\SIDE_collection_<device>_<time>.zip`. [1] chains only (no conversation text), [2] with session logs (contains conversation text). | 사건 이후 실행합니다. 서비스를 멈추고 한 번 더 훑은 뒤 체인과 기록부를 서명 없이 봉인하고 C2–C4를 확인해 `collections\SIDE_collection_<단말>_<시각>.zip`을 만듭니다. [1] 체인만(대화 원문 없음), [2] 세션 로그 포함(대화 원문 포함). |
| 9 | `9_uninstall.bat` | Type `Y`. Stops the service normally and deletes the scheduled task. The records stay. | `Y`를 입력합니다. 서비스를 정상 정지하고 예약 작업을 지웁니다. 기록은 남습니다. |

A sealed service folder accepts no more binding. To keep recording after a collection, run `1_install.bat`
again. The previous install moves aside, not deleted, and the PC enrolls anew. After `9_uninstall.bat`, the
next `1_install.bat` continues in the unsealed folder without a new enrollment.

봉인된 서비스 폴더에는 더 묶을 수 없습니다. 수거 뒤에도 계속 기록하려면 `1_install.bat`를 다시 실행합니다.
이전 설치는 지우지 않고 따로 옮겨 두며, PC는 새로 가입합니다. `9_uninstall.bat` 뒤의 `1_install.bat`는 봉인되지
않은 폴더에서 새 가입 없이 이어 묶습니다.

---

## 3. Where files go / 파일 위치

| Path | Meaning | 의미 |
|------|---------|------|
| `employee\seal_pub.hex` | Seal public key, in | 봉인 공개 키(조직에서 받아 넣는 파일) |
| `employee\collections\SIDE_collection_*.zip` | Collection for the organization, out. Key files are not included. | 조직에 보낼 수거본(여기에 만들어짐). 키 파일은 들어 있지 않음 |
| `<USB>\SIDE_custody_<device>_<time>\` | `k0.hex`, `enroll.json`, `seal_pub.hex`. Kept by the organization, never on this PC | `k0.hex`, `enroll.json`, `seal_pub.hex`. 조직이 보관하며 이 PC에 두지 않음 |
| `%ProgramData%\SIDE\` | Service code (`bin\`), service folder (`store\`), stop file and K0 until moved (`org\`), logs. SYSTEM and Administrators only | 서비스 코드(`bin\`), 서비스 폴더(`store\`), 정지 파일과 옮기기 전의 K0(`org\`), 로그. SYSTEM과 Administrators만 접근 |
| `%ProgramData%\SIDE_previous_install_<time>\` | A previous install moved aside by a new install | 다시 설치할 때 따로 옮겨 둔 이전 설치 |

The service binds the session logs of Claude Code (`.claude\projects`), Codex CLI (`.codex\sessions`), and
Antigravity editor and CLI (`.gemini\antigravity{,-cli}\brain`) in the employee profile. It only reads them
and uses no network.

서비스는 직원 프로필의 Claude Code(`.claude\projects`), Codex CLI(`.codex\sessions`), Antigravity 편집기와
CLI(`.gemini\antigravity{,-cli}\brain`) 세션 로그를 묶습니다. 읽기만 하며 네트워크를 쓰지 않습니다.

<details>
<summary>Command line / 명령줄</summary>

Run inside this folder, in a terminal opened as administrator. See [docs/guide.md](../docs/guide.md).
관리자 권한으로 연 터미널에서 이 폴더로 이동해 실행합니다. [docs/guide.md](../docs/guide.md)를 참고하세요.

```
python lib\side.py employee install [--employee <account>] [--key-out <folder>] [--fresh]
python lib\side.py employee root-key [--key-out <folder>]
python lib\side.py employee status
python lib\side.py employee collect [--include-logs] [--out <folder>]
python lib\side.py employee uninstall
```

</details>
