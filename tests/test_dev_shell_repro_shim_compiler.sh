#!/usr/bin/env bash
# Exercise the real recipe, Nim wrapper, compiler and monitor; no mocked tools.
# The Linux dev shell includes Clang and exports CC=clang, but these two
# actions declare GCC alone. Force execution so cached outputs cannot hide a
# compiler selection that contradicts the action's tool declaration.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -s)" in
  Linux) ;;
  *) echo 'This regression requires Linux and its GCC shim actions.' >&2; exit 1 ;;
esac

if [ "${1:-}" != --inside ]; then
  repro="$(command -v "${IO_MON_TEST_REPRO:-repro}")"
  exec nix develop "$repo" --no-write-lock-file \
    --command bash "$repo/tests/test_dev_shell_repro_shim_compiler.sh" --inside "$repro"
fi
repro="$2"
cd "$repo"
export CC=clang CXX=clang++
printf 'Testing %s with CC=%s CXX=%s; Nim: %s\n' "$repro" "$CC" "$CXX" "$(command -v nim)"
reports=build/compiler-selection-regression
mkdir -p "$reports"
failed=0
for target in shim test-monitor-runtime; do
  "$repro" graph --tool-provisioning=nix --json ".#$target" \
    >"$reports/$target-graph.json"
  touch "$reports/$target.started"
  # Keep both reports, including a failed compile's compiler diagnostics.
  if ! "$repro" build --daemon=off --tool-provisioning=nix --force-rebuild \
    ".#$target" "--write-report=$reports/$target.json" \
    >"$reports/$target.log" 2>&1; then
    cat "$reports/$target.log" >&2
    failed=1
  fi
done
[ "$failed" -eq 0 ] || exit 1

python3 -I - "$reports" <<'PY'
import json
from pathlib import Path
import sys

reports = Path(sys.argv[1])
for target, action_id, output in (
    ("shim", "io-mon.shim.build_shim", "build/lib/librepro_monitor_shim.so"),
    ("test-monitor-runtime", "io-mon.shim.build_test_monitor_runtime",
        "build/monitor-test-runtime/librepro_monitor_shim.so"),
):
    report = json.loads((reports / f"{target}.json").read_text())
    graph = json.loads((reports / f"{target}-graph.json").read_text())
    declarations = [a for a in graph["actions"] if a["id"] == action_id]
    assert len(declarations) == 1, (target, declarations)
    refs = declarations[0]["toolIdentityRefs"]
    assert "gcc" in refs and "clang" not in refs, (target, refs)
    actions = [a for a in report["actions"] if a["id"] == action_id]
    assert len(actions) == 1, (target, actions)
    action = actions[0]
    assert action["launched"], action
    assert action["status"] == "asSucceeded" and action["exitCode"] == 0, action
    assert action["dependencyPolicyKind"] == "dgAutomaticMonitor", action
    assert action["leaseId"] > 0 and not report["runQuota"]["bypassed"], action
    reads = action["evidence"]["monitorReads"]
    assert any(p.endswith("/bin/gcc") for p in reads), (target, reads)
    assert not any(p.endswith("/bin/clang") for p in reads), (target, reads)
    assert Path(output).is_file() and Path(output).stat().st_size > 0, output
    assert Path(output).stat().st_mtime_ns >= (reports / f"{target}.started").stat().st_mtime_ns, output
    print(f"PASS: {action_id} compiled its real shim under automatic monitoring and RunQuota with ambient CC=clang")
PY
