"""Compare the real, identical IPC fixture under two execution policies.

No mocks: compile through Reprobuild, run every existing assertion, and retain
an enclosing-monitor negative control before and after two uncached runs.
Only the recipe's collection selector and execution policy change in this job.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path.cwd()
RECIPE = ROOT / "repro.nim"
EVIDENCE = ROOT / "build/diagnostics/linux-ipc-isolation"
ACTION = "io-mon.test_execute.test_io_mon_linux_stdio_ipc"
BUILD_ACTION = "io-mon.test_build.test_io_mon_linux_stdio_ipc"
ARTIFACTS = [
    ROOT / "build/test-bin/test_io_mon_linux_stdio_ipc",
    ROOT / "build/bin/io-mon",
    ROOT / "build/lib/librepro_monitor_shim.so",
]


def hashes():
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in ARTIFACTS
    }


def execute(label, isolated):
    with tempfile.TemporaryDirectory(prefix="ipc-policy-report-") as temporary:
        report = Path(temporary) / "report.json"
        with (EVIDENCE / f"{label}.log").open("w") as log:
            result = subprocess.run(
                [
                    "repro", "build", ".#test-linux-ipc-diagnostic",
                    "--tool-provisioning=nix", "--daemon=off",
                    f"--write-report={report}",
                ],
                stdout=log, stderr=subprocess.STDOUT, timeout=1200,
            )
        data = json.loads(report.read_text())
    actions = {action["id"]: action for action in data["actions"]}
    action = actions[ACTION]
    summary = {
        "label": label,
        "command_exit": result.returncode,
        "artifacts": hashes(),
        "execution": {
            key: action[key]
            for key in ["id", "status", "exitCode", "launched", "cacheDecision",
                        "dependencyPolicyKind", "stdout", "stderr"]
        },
        "compile_policy": actions[BUILD_ACTION]["dependencyPolicyKind"],
    }
    (EVIDENCE / f"{label}.summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({key: value for key, value in summary.items()
                      if key not in ["execution"]}), flush=True)
    assert summary["compile_policy"] == "dgAutomaticMonitor", summary
    assert action["launched"], summary
    if isolated:
        assert result.returncode == 0, summary
        assert action["status"] == "asSucceeded" and action["exitCode"] == 0, summary
        assert action["cacheDecision"] == "cdNotCacheable", summary
        assert action["dependencyPolicyKind"] == "dgDepfile", summary
    else:
        assert result.returncode != 0 and action["status"] == "asFailed", summary
        assert action["dependencyPolicyKind"] == "dgAutomaticMonitor", summary
        assert "cap.code was 139" in action["stdout"], summary
    return summary["artifacts"]


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    original = RECIPE.read_text()
    selector = '    discard collect("test", testExecuteActions)\n'
    assert original.count(selector) == 1
    selected = original.replace(selector, selector + '''    var ipcDiagnosticActions: seq[BuildActionDef] = @[]
    for action in testExecuteActions:
      if action.id == "io-mon.test_execute.test_io_mon_linux_stdio_ipc":
        ipcDiagnosticActions.add(action)
    if ipcDiagnosticActions.len > 0:
      discard collect("test-linux-ipc-diagnostic", ipcDiagnosticActions)
''')
    marker = '          "test_io_mon_linux_fragment_fd_reuse.nim"]) or'
    assert selected.count(marker) == 1
    isolated = selected.replace(marker,
        '          "test_io_mon_linux_fragment_fd_reuse.nim",\n'
        '          "test_io_mon_linux_stdio_ipc.nim"]) or')
    try:
        RECIPE.write_text(selected)
        baseline = execute("monitored-before", isolated=False)
        RECIPE.write_text(isolated)
        assert execute("isolated-first", isolated=True) == baseline
        assert execute("isolated-repeat", isolated=True) == baseline
        RECIPE.write_text(selected)
        assert execute("monitored-after", isolated=False) == baseline
        print("Identical fixture, CLI and shim hashes; two real isolated executions; "
              "both monitored negative controls reproduce child exit 139.", flush=True)
    finally:
        RECIPE.write_text(original)


if __name__ == "__main__":
    main()
