# io-mon Linux non-file/path fidelity campaign

Target: /home/zahary/m/dev/io-mon-hardening-work, dev d2c451d5e009cc6ccd74b5eb5388e2b525825651.
OS: Linux.
Scratch: /tmp/io_mon_campaign_nonfile_path.

Harness:
- Built fresh shim with ./scripts/build_shim.sh: build/lib/librepro_monitor_shim.so.
- Used existing build/bin/io-mon CLI because nimble was not on PATH.
- Smoke baseline: baseline_open_read captured marker.txt as file-open and file-read with completeness=mcComplete.
- fopen/fread smoke did not capture file records; not used as a confirmation baseline for this campaign.

Confirmed mcComplete misses:
1. Non-file observed inputs are absent: getenv(IO_MON_MARKER_ENV), uname, sysconf(_SC_NPROCESSORS_ONLN), clock_gettime, gettimeofday all leave only process/profile records and completeness=mcComplete.
2. Entropy is absent as non-determinism: getrandom leaves no non-deterministic record and completeness=mcComplete. /dev/urandom is captured as file-open/file-read on /dev/urandom, but no non-deterministic marker/downgrade is emitted.
3. Path probes are incomplete and non-canonical: stat/lstat through a symlink record the symlink spelling only, not the canonical target; relative data/./link.txt stays relative. access, readlink, and statx leave no path-probe records at all, with completeness=mcComplete.
4. O_RDWR mmap-read input is classified as write only: open(O_RDWR) + mmap(PROT_READ, MAP_PRIVATE) records a single file-open observationKind=file-write for rdwr.txt, no read/input record, completeness=mcComplete.
5. Hardlink creation is invisible: link(source, dest) succeeds with no source or dest record and completeness=mcComplete.

Caught / not counted:
- Explicit open(O_RDONLY)+read is captured.
- /dev/urandom path itself is captured; the miss is semantic non-determinism, not path absence.
- MAP_SHARED writeback currently gets a file-write only because Linux O_RDWR is already classified as write. This is not proof of mmap coverage; if O_RDWR is fixed to input-or-both, MAP_SHARED writes need their own hook or they become an output miss.
- Reflink ioctl failed on this filesystem; not confirmed.

Saved depfiles and inspect text are under /tmp/io_mon_campaign_nonfile_path/run/.
