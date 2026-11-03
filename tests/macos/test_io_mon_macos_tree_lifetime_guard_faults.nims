# Compile this ONE test with the macOS tree-guard fault seam. The seam exists
# only under this define, so it is absent from every shipped artefact and from
# every other test binary; see the header of
# test_io_mon_macos_tree_lifetime_guard_faults.nim for why it is needed.
switch("define", "ioMonMacosTreeGuardFaultTest")
