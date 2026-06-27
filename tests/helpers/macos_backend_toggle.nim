## Shared test helper: translate the legacy macOS "backend" A/B names into the
## new DEBUG-ONLY per-mechanism diagnostic toggles.
##
## The user-facing `IO_MON_MACOS_BACKEND` selector was REMOVED: on macOS the shim
## always runs BOTH monitoring mechanisms (interpose + body-patch) by default.
## For DIAGNOSIS, NON-release (debug) shims honour two per-mechanism disable
## toggles, each its own env var:
##   * IO_MON_DEBUG_DISABLE_BODYPATCH=1 → interpose only (body-patch skipped)
##   * IO_MON_DEBUG_DISABLE_INTERPOSE=1 → body-patch only (interpose stops
##     recording; its thunks forward to the named/body-patched entry)
##
## The tests still want to exercise the three historical A/B states, so this
## helper maps them onto the toggles (single source of truth, DRY):
##   * "both"      → set NEITHER toggle (the default — both mechanisms record).
##   * "interpose" → IO_MON_DEBUG_DISABLE_BODYPATCH=1 (interpose only).
##   * "bodypatch" → IO_MON_DEBUG_DISABLE_INTERPOSE=1 (body-patch only).
##
## IMPORTANT: the toggles take effect ONLY in a NON-release (debug) shim. The
## tests build the shim via `scripts/build_shim.sh`, whose default
## `IO_MON_BUILD_MODE=debug` produces exactly such a shim, so the A/B arms work.
## In a release shim the toggles are no-ops (both mechanisms always on), so an
## A/B test built against a release shim would NOT see a disabled mechanism.

import std/strtabs

proc applyMacosBackendToggle*(env: StringTableRef; backend: string) =
  ## Set the DEBUG-only mechanism toggle(s) corresponding to the legacy
  ## `backend` name ("both" | "interpose" | "bodypatch"). Idempotently clears
  ## any previously-set toggle so the same `env` can be reused across arms.
  env.del("IO_MON_DEBUG_DISABLE_BODYPATCH")
  env.del("IO_MON_DEBUG_DISABLE_INTERPOSE")
  case backend
  of "both":
    discard  # default: both mechanisms record, no toggle.
  of "interpose":
    env["IO_MON_DEBUG_DISABLE_BODYPATCH"] = "1"
  of "bodypatch":
    env["IO_MON_DEBUG_DISABLE_INTERPOSE"] = "1"
  else:
    raise newException(ValueError,
      "unknown macOS backend A/B name: " & backend &
      " (expected both|interpose|bodypatch)")
