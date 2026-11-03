# Compile this ONE test with the Windows job-guard fault seam. The seam exists
# only under this define, so it is absent from every shipped artefact and from
# every other test binary; see the header of
# test_io_mon_windows_tree_lifetime_guard_faults.nim for why it is needed.
switch("define", "ioMonWindowsJobGuardFaultTest")
