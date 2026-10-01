# The Linux entropy fixture rejects a valid random byte

|             |                                                                           |
| ----------- | ------------------------------------------------------------------------- |
| Status      | open                                                                      |
| Recorded    | 2026-10-01                                                                |
| Observed in | io-mon `13d12f3f177f52070a7708d92385bb11f5857b27`                         |
| Area        | `tests/linux/test_io_mon_linux_stdio_ipc.nim`, non-file determinism probe |

## Observed

[Native Linux job 110470015874](https://github.com/metacraft-labs/io-mon/actions/runs/36892095599/job/110470015874)
fails only the entropy probe's successful-exit assertion:

```text
Check failed: cap.code == 0
cap.code was 9
```

After every environment, system, clock, and entropy API call succeeds, the
probe returns `rnd[0] == 255 ? 9 : 0`. Exit 9 therefore identifies a successful
entropy read whose first byte is 255. That valid value occurs with probability
1/256. All of this case's subsequent capture and completeness assertions pass.
The arbitrary rejection has existed since `e50df6c`; the private-shim fixture
repair did not introduce it.

## Expected

The `mrNonDeterministic` contract in [types.nim](../src/io_mon/types.nim) and
[Non-File Tracking](../docs/contributors/architecture.md) requires recording
observed entropy use. It imposes no constraint on the value returned by a real
entropy source. The fixture must accept every valid byte after a successful
read, while retaining its API-failure checks and all capture assertions.

## Suggested repair

Print the consumed byte and return success after the successful API checks.
Keep the real `getrandom` call, its full-length check and diagnostic, and the
existing `cap.code == 0`, completeness, and entropy-record assertions. No mock
or retry is needed to conceal the arbitrary output-value rejection.

## Search

Fetched `agents` and `dev` at `13d12f3` and `2d07041`. Searched open and deleted
issues for entropy flakiness, random exit values and `rnd[0]`; no matching record
was found. The repository-wide test search found this one rejection. CI log:
`/tmp/io-mon-13d-linux-native-promotion.log`.
