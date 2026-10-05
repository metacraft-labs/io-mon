---
title: Evidence Scope & Hazards
description: Detailed comparison of full vs reads-only evidence scopes, the one-directional invalidation hazard, and API safety.
section: guides
order: 3
---

# Evidence Scope & Hazards

The `--evidence` option governs how much of what `io-mon` observes is recorded into the final depfile.

```bash
io-mon run --evidence=full        # default
io-mon run --evidence=reads-only
```

---

## The Two Evidence Scopes

- **`full` (Default)**: Records every observation, including **failed lookups** — searches for files that do not exist (e.g. `ENOENT` from searching include paths).
- **`reads-only`**: Records only lookups that **found something** (successful reads and file opens).

### Why `reads-only` Exists

During compilation, tools search many directories for headers, modules, or configurations. In typical builds, search operations vastly outnumber actual reads:

- Compilers with dozens of `-I` search flags may check 20 non-existent paths before finding a single header.
- On a benchmark Nim compilation with 81 search directories, switching from `full` to `reads-only` reduced depfile records from **8,663 to 2,548 (-70.6%)**, with all dropped records being failed existence lookups.
- `reads-only` enables direct, like-for-like comparison with traditional compiler-emitted depfiles (e.g. `gcc -MD`), which record only opened headers and never failed probes.

---

## The One-Directional Hazard

While `reads-only` saves significant storage and deduplication time, it introduces a specific invalidation hazard:

| Change in your filesystem                                    | Detected under `full`? | Detected under `reads-only`? |
| :----------------------------------------------------------- | :--------------------- | :--------------------------- |
| A file read by the build is **modified**                     | ✓ Yes                  | ✓ Yes                        |
| A file read by the build is **deleted**                      | ✓ Yes                  | ✓ Yes                        |
| A new file is **added** earlier in a search path (shadowing) | ✓ Yes                  | ✗ **No**                     |
| A previously unreadable file becomes readable (`chmod`)      | ✓ Yes                  | ✗ **No**                     |

### Concrete Worked Example

Consider a C project built with `-I/project/include -I/project/vendor`:

1. `main.c` contains `#include "config.h"`.
2. The compiler checks `/project/include/config.h` (not found).
3. The compiler checks `/project/vendor/config.h` (found and read).

**Under `full` evidence:**
Both the failed lookup (`/project/include/config.h`) and the successful read (`/project/vendor/config.h`) are recorded. If a developer later creates `/project/include/config.h`, the build system sees that a probed path changed state, invalidating the cache and triggering a recompile.

**Under `reads-only` evidence:**
Only `/project/vendor/config.h` is recorded. If `/project/include/config.h` is created, the build system has no record that the compiler ever checked that path. The cache reports the action as "up to date", compiling against the stale vendor header.

---

## What `reads-only` Does Not Affect

1. **Build Artefact Integrity**: The output binaries generated are identical regardless of evidence scope; only the recorded dependency list differs.
2. **Completeness Grading**: Opting into `reads-only` is an intentional policy choice, not a monitoring error. It does not downgrade `mcComplete` to `mcIncomplete`. Real monitoring failures or event drops still downgrade completeness immediately.

---

## Checking Evidence Scope in Code

Every `.iomon` file records the evidence scope under which it was generated. Consumers written in Nim should verify scope compatibility:

```nim
import io_mon

let dep = readMonitorDepFile("build.iomon")

# Ensure the capture provides full evidence:
if not observedEvidenceScopeCovers(dep, esFull):
  if statesUnevaluableEvidenceScope(dep):
    echo "Depfile declares unfamiliar scope: ", dep.observedEvidenceScopeToken
  # Recompute or fall back to safe re-run
```

- An absent scope stamp defaults to `esFull` for backwards compatibility.
- Full evidence is strictly stronger than `reads-only`, so full captures are always valid for `reads-only` consumers.
