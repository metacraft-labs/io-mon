## A musl C compiler, for the test that the Linux shim refuses to compile
## against a libc other than glibc. A distinct name keeps it from shadowing
## the glibc `gcc` every other edge compiles with.
import repro_project_dsl

package `io-mon-test-musl-cc`:
  provisioning:
    nixPackage ".#io-mon-test-musl-cc",
      executablePath = "bin/io-mon-test-musl-cc"
