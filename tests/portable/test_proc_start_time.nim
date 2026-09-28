## The strict Linux descendant-prune boundary. No mocks: this exercises the
## pure predicate used by the actual /proc scan with exact timestamp values.
## Real detached-process and quiescent controls remain in the Linux suite.
import std/unittest
import io_mon/proc_start_time

suite "process start-time prune":
  test "only a known strictly earlier process predates the root":
    check predatesRoot(41, 42)
    check not predatesRoot(42, 42)
    check not predatesRoot(43, 42)
    check not predatesRoot(0, 42)
    check not predatesRoot(42, 0)
    check not predatesRoot(0, 0)
