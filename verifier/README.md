# SIDE verifier folder

The verifier (an auditor, opposing party, or regulator) uses this folder to check a disclosure package from
the organization. It needs only the package and the seal public key the organization published in advance,
not the root key or the whole chain. The tools only read files and use no network.

검증자(감사인·소송 상대·규제 기관)는 이 폴더로 조직이 보낸 제출 패키지를 검증합니다. 패키지와 조직이 미리
공개한 봉인 공개 키만 있으면 되며, 루트 키나 체인 전체는 필요 없습니다. 도구는 파일을 읽기만 하고 네트워크를
쓰지 않습니다.

This folder works on its own. Copy it whole, including `lib\`. It needs Python 3.10 or later from python.org.
이 폴더는 따로 동작합니다. `lib\`까지 폴더 전체를 복사합니다. python.org의 Python 3.10 이상이 필요합니다.

---

## 1. Steps / 단계

| Step | Double click | What happens | 하는 일 |
|:---:|--------------|--------------|--------|
| 1 | `1_viewer.bat` | Opens the viewer window. Choose `seal_pub.hex` with *Choose file…* (or paste its 64-digit value), click *Package view*, and pick `SIDE_disclosure_*.json`. It shows the three layers, the gap report, the scope statement, and the verdict. | 검증 창을 엽니다. *Choose file…*로 `seal_pub.hex`를 고르거나 64자리 값을 붙여 넣고, *Package view*를 눌러 `SIDE_disclosure_*.json`을 고릅니다. 세 계층, 공백 보고, 범위 진술, 판정을 보여 줍니다. |
| 2 | `2_check_package.bat` | The same check in a command window. Drag in the package. It uses `seal_pub.hex` in this folder if present (otherwise asks) and a same-name `.lines.jsonl` next to the package automatically. Ends with `Done.` (pass) or `Finished with exit code 1` (reject). | 같은 검증을 명령 창에서 합니다. 패키지를 끌어 놓습니다. 이 폴더에 `seal_pub.hex`가 있으면 쓰고(없으면 물음), 패키지 옆의 같은 이름 `.lines.jsonl`을 스스로 찾습니다. `Done.`(통과) 또는 `Finished with exit code 1`(거부)로 끝납니다. |

The window needs Python with *tcl/tk and IDLE* (the python.org default). Only step 2 compares the line text
in `.lines.jsonl`; the window does not.

창을 쓰려면 *tcl/tk and IDLE*이 켜진 Python(python.org 기본값)이 필요합니다. `.lines.jsonl`의 원문 대조는
2단계만 하며 창은 하지 않습니다.

---

## 2. What the verdict means / 판정의 의미

| Layer | Question | 묻는 것 |
|-------|----------|--------|
| 1 Inclusion | Do the disclosed records hang from the Merkle root of this package (inclusion proof)? | 제출된 레코드가 이 패키지의 머클 루트에 포함되는가(포함 증명)? |
| 2 Record count | Does the total record count in the package equal the count in the seal body? | 패키지의 전체 레코드 수가 봉인 본문의 수와 같은가? |
| 3 Seal signature | Does the seal point to this root, and did the organization sign it? | 봉인이 이 루트를 가리키고, 조직이 서명했는가? |

| Verdict | Meaning | 의미 |
|---------|---------|------|
| accept | All three layers and the gap report pass | 세 계층과 공백 보고가 모두 통과 |
| accept (withheld) | Nothing disagrees, but something was not judged: no public key given, or no gap report | 어긋난 것은 없지만 판단하지 못한 항목이 있음: 공개 키 없음, 공백 보고 없음 등 |
| reject | A layer or the gap report disagrees, or the seal is unsigned while *Reject if unsigned* is on (default) | 계층이나 공백 보고가 어긋나거나, *Reject if unsigned*(기본값)가 켜진 채 봉인에 서명이 없음 |
| no verdict possible | The package discloses no records or has an empty Merkle root, so nothing can disagree | 제출 레코드가 없거나 머클 루트가 비어 어긋날 것이 없음 |

The gap report lists, with proofs against the sealed device ledger, the windows the service missed (abnormal
stops, automatic restarts, read failures). The scope statement gives the selection rule, the disclosed records,
and the period. The layers show only whether the disclosure broke its declared scope. Nobody can know what the
undisclosed records contained, and the window says so under *What was not confirmed*.

공백 보고는 봉인된 단말 기록부에 대한 증명과 함께 서비스가 놓친 구간(비정상 정지, 자동 재시작, 읽기 실패)을
보여 줍니다. 범위 진술은 선택 규칙, 제출 레코드, 기간을 밝힙니다. 계층들은 제출이 밝힌 범위를 어겼는지만
보여 줍니다. 제출하지 않은 레코드의 내용은 누구도 알 수 없으며, 창은 이를 *What was not confirmed*에 적습니다.

---

## 3. Obtain the public key separately / 공개 키는 따로 받기

Use the `seal_pub.hex` the organization published in advance through another channel. Any file name works.
Never use a key that came inside or with the package: a discloser who makes a new seal and includes the
matching key would pass with it. Without a key, layers 1 and 2 and the seal root still run, but the
organization signature is not judged.

조직이 다른 경로로 미리 공개한 `seal_pub.hex`를 씁니다. 파일 이름은 상관없습니다. 패키지 안에 있거나 함께 온
키는 쓰지 않습니다. 새 봉인을 만들고 맞는 키를 넣은 제출자는 그 키로 당연히 통과합니다. 키가 없어도 1·2계층과
봉인 루트는 확인하지만 조직 서명은 판단하지 않습니다.

---

## 4. Why viewing is separate from binding / 보기와 묶기를 나눈 이유

SIDE rests on one premise: the person who leaves a record cannot change it, so the system account binds. A
window with user rights that could touch a chain would let the record owner change it. The viewer therefore
only reads files, never shows the root key (only its commitment), and never shows conversation text (a chain
holds only hashes and byte offsets). Every verdict comes from the same code that `side_service.py --verify` and `--verify-package` run.

SIDE는 기록을 남기는 사람이 그 기록을 바꿀 수 없다는 전제에 서 있으며, 그래서 system 계정이 묶습니다. 사용자
권한 창이 체인을 건드릴 수 있다면 기록의 주인이 그 창으로 기록을 바꿀 수 있습니다. 그래서 검증 창은 파일을
읽기만 하고, 루트 키는 보여 주지 않고(커밋먼트 값만), 대화 원문도 보여 주지 않습니다(체인에는 해시와 바이트 위치만
있음). 모든 판정은 `side_service.py --verify`와 `--verify-package`가 쓰는 코드가 그대로 내립니다.

---

## 5. Chain view / 체인 보기

*Chain view* is for the organization or an investigator who holds a whole collection. Choose the
`received\<zip name>\` folder (its parent also works), then the custody `k0.hex`. It shows the enrollment
certificate, the device ledger, checks C1–C4 per session chain, and how many chains carry a forgery signal.
Cancel the key dialog to skip C1 and the commitment check. C3 and C4 run only when the collection includes
session logs.

*Chain view*는 수거본 전체를 가진 조직이나 조사자가 씁니다. `received\<zip 이름>\` 폴더(상위 폴더도 됨)를 고르고,
이어 보관본의 `k0.hex`를 고릅니다. 가입 증서, 단말 기록부, 세션 체인별 C1–C4 결과, 위조 신호가 있는 체인 수를
보여 줍니다. 키 창을 취소하면 C1과 커밋먼트 확인을 건너뜁니다. C3와 C4는 수거본에 세션 로그가 있을 때만 실행됩니다.

| Check | Question | 묻는 것 |
|-------|----------|--------|
| C1 Tag recomputation | Did a record or the record order change after binding? | 묶인 뒤 레코드나 순서가 바뀌었는가? |
| C2 Offset continuity | Do the bound byte ranges continue without a hole? | 묶인 바이트 범위가 빈틈없이 이어지는가? |
| C3 Line hash vs file | Does the session log at each offset still match the bound line? | 각 위치의 세션 로그가 묶인 행과 여전히 같은가? |
| C4 Checkpoint size | Is the session log now smaller than a checkpoint recorded? | 세션 로그가 체크포인트에 적힌 크기보다 작아졌는가? |

---

## 6. Easy misreadings / 잘못 읽기 쉬운 것

| Shown | Meaning | 의미 |
|-------|---------|------|
| Service state: an interval is still open | A `service_start` has no `service_stop`. The service may still be running, or someone killed it; the two cannot be told apart at verification time. | `service_start` 뒤에 `service_stop`이 없습니다. 서비스가 아직 실행 중이거나 누군가 강제로 종료했을 수 있으며, 검증 시점에는 둘을 구분할 수 없습니다. |
| session log absent | Normal when the collection holds chains only. C3 and C4 did not run, so it shows in yellow. | 체인만 수거했다면 정상입니다. C3와 C4가 돌지 않았으므로 노란색으로 표시합니다. |
| A C2 offset gap and other signals | Each signal has causes other than tampering, such as a service stop or agent compaction. Compare it with the stops and read failures in the ledger. | 신호마다 서비스 정지나 에이전트의 대화 압축처럼 조작이 아닌 원인이 있을 수 있습니다. 기록부의 정지와 읽기 실패와 대조합니다. |

---

## 7. Where files go / 파일 위치

| Path | Meaning | 의미 |
|------|---------|------|
| `verifier\seal_pub.hex` | Optional. `2_check_package.bat` uses it without asking | 선택. `2_check_package.bat`가 묻지 않고 씀 |
| `SIDE_disclosure_*.json` | The package received from the organization, anywhere | 조직에서 받은 패키지, 위치 무관 |
| `SIDE_disclosure_*.lines.jsonl` | Optional line text, next to the package with the same name | 선택. 같은 이름으로 패키지 옆에 두는 행 원문 |

<details>
<summary>Command line / 명령줄</summary>

Run inside this folder. See [docs/guide.md](../docs/guide.md).
이 폴더 안에서 실행합니다. [docs/guide.md](../docs/guide.md)를 참고하세요.

```
python lib\side.py verifier
python lib\side.py verifier check <SIDE_disclosure_*.json> --seal-public-key <seal_pub.hex or 64-digit value> [--lines <*.lines.jsonl>]
```

The command line prints `verdict: pass` or `verdict: reject` (exit code 0 or 1) and always requires the seal
signature. For the chain view without a window:

명령줄은 `verdict: pass` 또는 `verdict: reject`(종료 코드 0 또는 1)를 출력하며 봉인 서명을 항상 요구합니다.
창 없이 체인 보기와 같은 검증을 하려면 다음을 씁니다.

```
set SIDE_STORE=<received\zip name>
python lib\side_service.py --verify --org-key <k0.hex> --seal-pub <seal_pub.hex> --require-sig [--sessions-dir <received\zip name>\sessions]
```

</details>
