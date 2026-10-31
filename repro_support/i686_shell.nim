## A real 32-bit loader-incompatible image for the Linux entry-loss oracle.
## Give it a distinct name: putting its bin/bash on PATH would also replace
## the ordinary 64-bit shell used by the test's monitored controls.
import repro_project_dsl

package `io-mon-test-i686-sh`:
  provisioning:
    nixPackage ".#io-mon-test-i686-sh",
      executablePath = "bin/io-mon-test-i686-sh"
