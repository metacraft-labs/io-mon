import std/os

switch("path", "src")
switch("path", "../nim-stackable-hooks/src")
switch("path", "tests/helpers")

# io-mon's shared-memory dependency queue (io_mon/shm/dep_queue) now sits on the
# extracted `shm_queue/ring` MPSC ring (metacraft-labs/nim-shm-queue). In this
# `repo`-managed workspace the sibling lives at ../nim-shm-queue/src; a consumer
# building io-mon from a read-only store path (Nix flake input) overrides that
# with $SHM_QUEUE_SRC — mirrors how scripts/build_shim.sh resolves
# STACKABLE_HOOKS_SRC. The path is added even when the dir is absent so a clear
# "cannot open file: shm_queue/ring" surfaces rather than a silent wrong build.
let shmQueueSrc = getEnv("SHM_QUEUE_SRC", "../nim-shm-queue/src")
switch("path", shmQueueSrc)

# io-mon-Lossless-Event-Capture M3 (part 1): the SET transport (metacraft-labs/
# nim-shm-set) is the new PRIMARY Linux dependency channel (Candidate C, the M1
# winner), replacing the DEP-SHM ring as the producer→consumer fast path while
# the `.rmdf-frag` file fallback stays in place (its deletion is part 2). Same
# sibling-checkout / $SHM_SET_SRC override discipline as $SHM_QUEUE_SRC above.
let shmSetSrc = getEnv("SHM_SET_SRC", "../nim-shm-set/src")
switch("path", shmSetSrc)
