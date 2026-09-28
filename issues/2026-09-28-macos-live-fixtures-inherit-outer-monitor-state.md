# macOS live fixtures inherit an outer monitor's state

- Status: open
- Observed: io-mon `de755e5`, local macOS ARM64, Reprobuild executable built
  from `4adfd0e7`, current provider source `90dc4321`, io-mon shim `de755e5`.

The complete native macOS suite passes in job `109087131146`. Running the same
catalog through `repro test` fails eight execution edges. Five fixtures stamp
their child records with a fixed test session but call `mergeFragments` without
that session: IPC breakaway, link-time entropy, vfork exit, residuals and XPC
breakaway. An inherited outer session filters their records away.

The setexec, path-canonicalization root guard and SIP system-child fixtures
deliberately need a launch without the outer shim's SIP executable rewriting.
Under the outer shim their blind controls unexpectedly capture reads and
report process starts. Every original assertion must remain enforced.

The host API session contract and `Monitor-Hook-Shim.md` require evidence to
belong to its actual run. Pass each fixture's existing `testRunId` explicitly
to the merge. For the three SIP launch experiments, use the existing isolated
execution policy with caching disabled, keeping compilation monitored. Verify
the full graph and prove those three execute again on a repeat invocation.

Evidence: `/tmp/io-mon-de755-macos-full-graph.json` and `.log`. Refreshed
`origin/dev` at `279a17b` (already an ancestor), searched open and deleted
issues for outer sessions and nested monitoring. The resolved host-session
issue fixed production host merges; these remaining merges belong to tests.
