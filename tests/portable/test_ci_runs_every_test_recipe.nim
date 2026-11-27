## Every `test*` recipe in the Justfile runs in some GitHub workflow.
##
## WHY.  A test that no workflow runs is a test nobody runs.  The real-build
## completeness oracle (`just test-realbuild-oracle`, the §4.5(h) cardinal-sin
## gate) sat in the Justfile with a header saying it was "suitable to keep in
## CI", and no workflow called it: the recipe, its script and its oracle binary
## appeared nowhere under `.github/`.  Nothing noticed, because nothing compared
## the two.  This test is that comparison, so the next recipe added without a
## CI step fails `just test` on every OS instead of going quietly unrun.  The
## rule it enforces is stated in docs/contributors/building-and-testing.md
## ("Every test recipe runs in CI").
##
## WHAT THIS CHECKS.  Every top-level Justfile recipe whose name starts with
## `test` must be SCHEDULED by the workflows in `.github/workflows/*.yml`, read
## with their comment lines removed.  A recipe is scheduled when
##   (a) a workflow line invokes `just <name>`, the name ending at a character
##       that cannot continue a recipe name (so `just test` does not schedule
##       `test-foo`, and `just test-foo` does not schedule `test`); or
##   (b) every non-comment line of its body appears verbatim in the workflow
##       text, i.e. a workflow runs the recipe's commands directly (the CI
##       engine-lock check is run that way, with extra arguments); or
##   (c) it is listed in `Subsumed` below as a strict subset of another
##       recipe.  So that table cannot hide an unrelated recipe, a subsumed
##       recipe's body and its parent's body must both run
##       `scripts/run_tests.nims`, and the parent must itself be scheduled by
##       (a) or (b).
## A recipe that genuinely cannot run in CI (it needs hardware CI lacks) is
## not exempted here silently: it must be documented as manual-only in
## building-and-testing.md, and this test extended with an explicit table for
## it.
##
## CONTROLS.  The parser must find `test` and `test-realbuild-oracle`, and at
## least one workflow must be read, or the verdict is vacuous.  The classifier
## is also run over a synthetic Justfile/workflow pair held in memory: an
## unscheduled recipe must be reported, a commented-out `# just <name>` line
## must not count, and a longer recipe name must not schedule its prefix.
##
## Limits, on purpose: this is a textual check.  It does not prove the step's
## `if:` ever selects a runner, and it does not strip a trailing `# ...`
## comment from a YAML line (a `just` invocation inside one would count).
##
## NO MOCKS: the real Justfile and the real workflow files of this checkout.
## The synthetic pair is a positive control for the classifier, not a stand-in
## for the real inputs.

import foreign_preload_isolation

import std/[algorithm, os, sequtils, strutils, tables]

const
  SelfSource = currentSourcePath()
  RootMarker = "io_mon.nimble"
    ## A file every checkout of this repository has, used to validate the
    ## derived checkout root.
  LevelsBelowRoot = 2
    ## How many directories this file sits below the checkout root.
  RunTestsScript = "scripts/run_tests.nims"
  Subsumed = {
    "test-portable": "test",
    "test-platform": "test",
  }
    ## Recipes that run a strict subset of another recipe's tests.  Both are
    ## arms of scripts/run_tests.nims (`-d:ioMonPortableTests` selects
    ## tests/portable, `-d:ioMonPlatformTests` the host-OS directories) out of
    ## the same directory set that `just test` runs in full on every lane.
  NameChars = {'A'..'Z', 'a'..'z', '0'..'9', '_', '-'}
    ## Characters a just recipe name can continue with.

type
  Recipe = object
    name: string
    body: seq[string]   ## Non-comment body lines, trimmed.

  Verdict = object
    name: string
    scheduled: bool
    how: string         ## Why it counts as scheduled, or why it does not.

var failures = 0

proc fail(msg: string) =
  inc failures
  echo "  FAIL  ", msg

proc pass(msg: string) =
  echo "  ok    ", msg

proc canonical(p: string): string =
  try: expandFilename(p) except OSError: p

proc parseJustfile(text: string): seq[Recipe] =
  ## The top-level recipes of a Justfile, with their bodies.  A recipe header
  ## is an unindented line holding a `:` that is not an assignment (`:=`),
  ## an alias, a setting, an attribute (`[private]`) or a comment; its name is
  ## the first token (a leading `@` quiet marker dropped), so parameters
  ## (`name arg="x":`, `name *args:`) and dependencies are not part of it.  Its
  ## body is the indented lines that follow, through blank lines, until the
  ## next unindented line.
  let lines = text.splitLines()
  var i = 0
  while i < lines.len:
    let line = lines[i]
    inc i
    if line.len == 0 or line[0] in {' ', '\t'}: continue
    let s = line.strip()
    if s.len == 0 or s.startsWith("#") or s.startsWith("["): continue
    if ":=" in s or ':' notin s: continue
    var head = s.split({' ', '\t', ':'}, maxsplit = 1)[0]
    if head in ["alias", "set", "export", "import", "mod"]: continue
    head.removePrefix('@')
    if head.len == 0: continue
    var r = Recipe(name: head)
    while i < lines.len and (lines[i].len == 0 or lines[i][0] in {' ', '\t'}):
      let b = lines[i].strip()
      inc i
      if b.len > 0 and not b.startsWith("#"):
        r.body.add b
    result.add r

proc withoutComments(yaml: string): string =
  ## The workflow text minus every line whose first non-space character is
  ## `#`, so a commented-out step schedules nothing.
  for line in yaml.splitLines():
    if line.strip().startsWith("#"): continue
    result.add line
    result.add '\n'

proc invokesJust(workflow, name: string): bool =
  ## Whether some `just <name>` in the text names exactly this recipe.
  let needle = "just " & name
  var at = workflow.find(needle)
  while at >= 0:
    let before = at == 0 or workflow[at - 1] notin NameChars
    let endAt = at + needle.len
    let after = endAt >= workflow.len or workflow[endAt] notin NameChars
    if before and after: return true
    at = workflow.find(needle, at + 1)
  false

proc directlyScheduled(r: Recipe; workflow: string): (bool, string) =
  ## Rules (a) and (b).
  if invokesJust(workflow, r.name):
    return (true, "a workflow runs `just " & r.name & "`")
  if r.body.len > 0:
    for b in r.body:
      if b notin workflow:
        return (false, "")
    return (true, "a workflow runs its body directly")
  (false, "")

proc classify(justfile, workflow: string;
              subsumed: openArray[(string, string)]): seq[Verdict] =
  ## A verdict for every `test*` recipe of `justfile` against the
  ## comment-stripped `workflow` text.
  let recipes = parseJustfile(justfile)
  var byName = initTable[string, Recipe]()
  for r in recipes: byName[r.name] = r
  var parentOf = initTable[string, string]()
  for (child, parent) in subsumed: parentOf[child] = parent
  for r in recipes:
    if not r.name.startsWith("test"): continue
    let (direct, how) = directlyScheduled(r, workflow)
    if direct:
      result.add Verdict(name: r.name, scheduled: true, how: how)
    elif r.name in parentOf:
      let parent = parentOf[r.name]
      if parent notin byName:
        result.add Verdict(name: r.name, how: "listed as subsumed by `" &
          parent & "`, which is not a recipe")
      elif not r.body.anyIt(RunTestsScript in it) or
           not byName[parent].body.anyIt(RunTestsScript in it):
        result.add Verdict(name: r.name, how: "listed as subsumed by `" &
          parent & "`, but the two do not both run " & RunTestsScript &
          ", so the subset claim does not hold")
      elif not directlyScheduled(byName[parent], workflow)[0]:
        result.add Verdict(name: r.name, how: "listed as subsumed by `" &
          parent & "`, which no workflow runs either")
      else:
        result.add Verdict(name: r.name, scheduled: true,
          how: "a subset of `" & parent & "` (" & RunTestsScript & " arm)")
    else:
      result.add Verdict(name: r.name, how: "no workflow runs `just " &
        r.name & "` or its body")

# ---------------------------------------------------------------------------
echo "ci-schedules-tests: [0] positive control on a synthetic pair"
block:
  const
    SynthJustfile = """
alias t := test
x := "y"
test:
    nim e scripts/run_tests.nims
test-run arg="--fast":
    run_it.sh {{arg}}
test-commented:
    commented.sh
test-direct:
    # a comment line is not part of the body
    direct.sh --a
test-sub:
    nim e -d:sub scripts/run_tests.nims
test-orphan-sub:
    other.sh
test-abc:
    abc.sh
"""
    SynthWorkflow = """
jobs:
  t:
    steps:
      - run: just test
      - run: dev-exec just test-run --full
      # - run: just test-commented
      - run: direct.sh --a --extra
      - run: just test-abcd
"""
  let v = classify(SynthJustfile, withoutComments(SynthWorkflow),
                   [("test-sub", "test"), ("test-orphan-sub", "test")])
  var got = initTable[string, bool]()
  for x in v: got[x.name] = x.scheduled
  let want = {"test": true, "test-run": true, "test-commented": false,
              "test-direct": true, "test-sub": true,
              "test-orphan-sub": false, "test-abc": false}
  if got.len != want.len:
    fail("synthetic Justfile: expected " & $want.len & " test recipes, the " &
         "parser found " & $got.len & ": " & $got)
  for (name, sched) in want:
    if name notin got:
      fail("synthetic Justfile: the parser did not find `" & name & "`")
    elif got[name] != sched:
      fail("synthetic `" & name & "`: classified " &
           (if got[name]: "scheduled" else: "unscheduled") & ", expected " &
           (if sched: "scheduled" else: "unscheduled"))
  if failures == 0:
    pass("an unscheduled recipe is reported, `# just ...` does not count, " &
         "a longer name does not schedule its prefix, and a bogus subsumed " &
         "entry is refused")

# ---------------------------------------------------------------------------
let selfFile = canonical(SelfSource)
var rootGuess = selfFile.parentDir
for _ in 1 .. LevelsBelowRoot:
  rootGuess = rootGuess.parentDir
let root = canonical(rootGuess)
if not fileExists(root / RootMarker):
  echo "ci-schedules-tests: cannot locate the checkout root from ", SelfSource,
    " (derived ", root, ", which has no ", RootMarker,
    "): refusing to report a verdict about an unknown tree"
  quit(2)
echo "ci-schedules-tests: checkout ", root

let justfileText =
  try: readFile(root / "Justfile")
  except IOError as e:
    echo "ci-schedules-tests: cannot read the Justfile: ", e.msg
    quit(2)

var workflowFiles: seq[string]
for f in walkFiles(root / ".github" / "workflows" / "*.yml"):
  workflowFiles.add f
sort(workflowFiles)
var workflowText = ""
for f in workflowFiles:
  try:
    workflowText.add withoutComments(readFile(f))
  except IOError as e:
    fail("cannot read workflow " & f & ": " & e.msg)

echo "ci-schedules-tests: [1] the inputs are not empty"
if workflowFiles.len == 0:
  fail("no .github/workflows/*.yml file was found: every verdict below " &
       "would be vacuous")
else:
  pass("read " & $workflowFiles.len & " workflow file(s)")
let recipeNames = parseJustfile(justfileText).mapIt(it.name)
for required in ["test", "test-realbuild-oracle"]:
  if required in recipeNames:
    pass("the Justfile parser found `" & required & "`")
  else:
    fail("the Justfile parser did not find `" & required & "`: either the " &
         "recipe was removed or the parser is broken, and the verdict is " &
         "vacuous either way")

echo "ci-schedules-tests: [2] every test recipe is scheduled"
for v in classify(justfileText, workflowText, Subsumed):
  if v.scheduled:
    pass("`" & v.name & "`: " & v.how)
  else:
    fail("`" & v.name & "` runs in no GitHub workflow (" & v.how & "). " &
         "Every test recipe must run in CI " &
         "(docs/contributors/building-and-testing.md); one that needs " &
         "hardware CI lacks must be documented there as manual-only")

if failures > 0:
  echo "ci-schedules-tests: FAILED, ", failures, " failure(s)"
  quit(1)
echo "ci-schedules-tests: PASS"
