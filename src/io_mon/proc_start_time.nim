## Internal start-time filter shared by the Linux process scan and its tests.
## Zero denotes unavailable evidence and must retain a candidate.

func predatesRoot*(startTicks, rootStartTicks: uint64): bool {.inline.} =
  rootStartTicks > 0 and startTicks > 0 and startTicks < rootStartTicks
