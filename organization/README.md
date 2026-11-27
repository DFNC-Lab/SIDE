# SIDE organization folder

Security staff of the organization run this folder on an organization PC, never on an employee PC. It
makes the seal key pair, signs the seal of each collection, verifies it with the root key K0, and builds
disclosure packages. It needs no administrator rights.

조직의 보안 담당이 조직 PC에서 이 폴더를 실행하며, 직원 PC에는 절대 두지 않습니다. 봉인 키 쌍을 만들고,
수거본마다 봉인에 서명하고 루트 키 K0로 검증하며, 제출 패키지를 만듭니다. 관리자 권한은 필요 없습니다.

This folder works on its own. Copy it whole, including `lib\`, to the organization PC. It needs Python 3.10 or later from python.org.
이 폴더는 따로 동작합니다. `lib\`까지 폴더 전체를 조직 PC에 복사합니다. python.org의 Python 3.10 이상이 필요합니다.

---

## 1. Steps / 단계

Each file ends with `Done.` or `Finished with exit code N`. To enter a path, drag the file or folder onto
the window and press Enter.

파일마다 `Done.` 또는 `Finished with exit code N`으로 끝납니다. 경로는 파일이나 폴더를 창에 끌어 놓고
Enter를 눌러 입력합니다.

| Step | Double click | What happens | 하는 일 |
|:---:|--------------|--------------|--------|
| 1 | `1_make_seal_key.bat` | Once. Makes `org_keys\seal_secret.hex` (private key, never leaves this PC) and `seal_pub.hex`. Copy `seal_pub.hex` into `employee\` before the install, and publish it to verifiers in advance through a channel other than the package. | 한 번만. `org_keys\seal_secret.hex`(개인 키, 이 PC를 떠나지 않음)와 `seal_pub.hex`를 만듭니다. `seal_pub.hex`는 설치 전에 `employee\`에 넣고, 검증자에게는 패키지와 다른 경로로 미리 공개합니다. |
| 2 | `2_receive_collection.bat` | Drag in `SIDE_collection_*.zip` and the `SIDE_custody_*` folder of that PC. It finds `org_keys\seal_secret.hex` itself. It checks the files against the manifest, compares the enrollment certificate and public key with the custody copy, signs the seal, and verifies every chain with K0 (C1–C4 with session logs, C1–C2 without). | `SIDE_collection_*.zip`과 그 PC의 `SIDE_custody_*` 폴더를 끌어 놓습니다. `org_keys\seal_secret.hex`는 스스로 찾습니다. 파일을 매니페스트와 대조하고, 가입 증서와 공개 키를 보관본과 비교한 뒤 봉인에 서명하고 K0로 모든 체인을 검증합니다(세션 로그가 있으면 C1–C4, 없으면 C1–C2). |
| 3 | `3_disclose.bat` | Pick a chain of the most recent collection and the record numbers (`5-9,12`), and optionally write a selection rule. [1] package only (no conversation text), [2] package and the text of those lines (`.lines.jsonl`), which needs a collection made with session logs. | 가장 최근 수거본에서 체인과 레코드 번호(`5-9,12`)를 고르고, 원하면 선택 규칙을 적습니다. [1] 패키지만(대화 원문 없음), [2] 패키지와 그 행의 원문(`.lines.jsonl`). [2]는 세션 로그를 포함해 수거한 경우에만 됩니다. |
| 4 | `4_verify_package.bat` | Preview. Checks a package in a command window with `organization\seal_pub.hex`, as the verifier will. | 미리 보기. 검증자와 똑같이 `organization\seal_pub.hex`로 명령 창에서 패키지를 확인합니다. |
| 5 | `5_viewer.bat` | Preview. Opens the verifier window (chain view and package view). | 미리 보기. 검증 창(체인 보기, 패키지 보기)을 엽니다. |

When step 2 reports `findings present`, read `verification_result.txt`. It lists the signals per chain, such
as a service interval without a stop record, a read failure (share-deny), a shrink, or a duplicate session
open. A signal alone is not evidence of tampering; a person decides.

2단계가 `findings present`를 보고하면 `verification_result.txt`를 읽습니다. 정지 기록 없는 서비스 구간,
읽기 실패(share-deny), 크기 감소, 중복 세션 열기 같은 신호를 체인별로 적어 둡니다. 신호 하나만으로는 조작의
증거가 아니며, 판단은 사람이 합니다.

---

## 2. Where files go / 파일 위치

| Path | Meaning | 의미 |
|------|---------|------|
| `org_keys\seal_secret.hex` | Seal private key. Never leaves this PC | 봉인 개인 키. 이 PC를 떠나지 않음 |
| `seal_pub.hex` | Seal public key for employee PCs and verifiers (same value as `org_keys\seal_pub.hex`) | 직원 PC와 검증자에게 줄 봉인 공개 키(`org_keys\seal_pub.hex`와 같은 값) |
| `SIDE_custody_*\` | Root key K0 and enrollment certificate of one PC, brought back by IT staff. Without it, C1 is impossible | IT 담당이 가져온 PC 하나의 루트 키 K0와 가입 증서. 없으면 C1을 할 수 없음 |
| `received\<zip name>\` | Extracted, signed collection and `verification_result.txt`. A zip already received is refused | 풀어서 서명한 수거본과 `verification_result.txt`. 이미 받은 zip은 거부 |
| `disclosures\SIDE_disclosure_*.json` | Disclosure package for the verifier, with `.lines.jsonl` when [2] was chosen | 검증자에게 보낼 제출 패키지. [2]를 고르면 `.lines.jsonl`도 함께 |

Send only the package (and the `.lines.jsonl` to a receiver entitled to read those lines). Do not send
`seal_pub.hex` with it: a key inside the package is a value the sender could change.

패키지만 보내고, `.lines.jsonl`은 그 행을 읽을 자격이 있는 사람에게만 보냅니다. `seal_pub.hex`를 함께 보내지
않습니다. 패키지 안의 키는 보내는 쪽이 바꿀 수 있는 값입니다.

<details>
<summary>Command line / 명령줄</summary>

Run inside this folder. See [docs/guide.md](../docs/guide.md).
이 폴더 안에서 실행합니다. [docs/guide.md](../docs/guide.md)를 참고하세요.

```
python lib\side.py organization seal-key [--dir <folder>]
python lib\side.py organization receive <SIDE_collection_*.zip> --custody <SIDE_custody_*> --seal-private-key <seal_secret.hex>
python lib\side.py organization disclose [--collection <received\...>] [--list] [--chain N] [--range 5-9,12] [--rule <text>] [--lines]
python lib\side.py organization verify-package <SIDE_disclosure_*.json> --seal-public-key <seal_pub.hex> [--lines <*.lines.jsonl>]
```

</details>
