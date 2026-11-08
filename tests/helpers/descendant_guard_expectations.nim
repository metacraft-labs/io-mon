## Subsystem oracles must keep rejecting every loss. This helper used to remove
## exactly one diagnostic, the platform-wide "no complete tree-lifetime guard"
## limitation, so that subsystem suites could grade what they test on a
## platform whose every capture carried it. It is for tests only; consumers
## must always honor the original verdict.
##
## No platform carries that limitation any more. Windows proves quiescence with
## its Job Object guard (docs/usage.md, the Windows tree-lifetime guard)
## and macOS with its kernel census (docs/usage.md, "The macOS tree-lifetime
## guard (normative)"), so on every platform this helper removes NOTHING: a
## suite that grades through it asserts the real, un-normalized completeness,
## and a healthy fixture must be complete on its own. The retired markers are
## deliberately not recognised, so one that ever reappeared would fail closed.
import io_mon

proc isDescendantLimitation*(record: MonitorRecord): bool =
  false

proc subsystemEvidence*(dep: MonitorDepFile): MonitorDepFile =
  dep

proc subsystemEvidence*(capture: MonitorResult): MonitorDepFile =
  subsystemEvidence(capture.depFile)
