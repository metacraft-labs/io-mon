# Compile this ONE test with the Linux descendant-guard round seam. The seam
# exists only under this define, so it is absent from every shipped artefact
# and from every other test binary; see the header of
# test_io_mon_linux_tree_guard_settle.nim for why it is needed.
switch("define", "ioMonLinuxTreeGuardFaultTest")
