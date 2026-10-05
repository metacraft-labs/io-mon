# SPDX-FileCopyrightText: 2026 Metacraft Labs / Schelling Point Labs
# SPDX-License-Identifier: Apache-2.0
## io-mon docs -- thin SSG entry.
##
## Calls the framework's own `buildDocsSite` scaffold with this site's `content/`
## dir and its own `DocsConfig`, passing NO explicit manifest -- letting the
## framework's default (`buildManifestFromContent`) auto-discover the route
## table, and its nav order via each page's `order:` front matter, from `content/`.
##
## The shared Metacraft docs token layer (`theme_tokens.metacraftDocsTokensCss`)
## is emitted to CSS and PREPENDED onto `assets/style.css`, and anything under
## `static/` is copied verbatim into `public/assets/` AFTER the hash/purge pass so
## the stylesheet's `url(/assets/...)` refs resolve to real files.

when defined(js):
  {.error: "build.nim is a C-target (SSG) entry; not for the JS target".}

import std/os
import docs_scaffold
import core/base_path
import ./docs_config
import ./theme_tokens

const basePathEnvVar* = "IO_MON_DOCS_BASE_PATH"

when isMainModule:
  let envBase = getEnv(basePathEnvVar, "/io-mon")
  let channelBase = normalizeBasePath(envBase)
  let n = buildDocsSite(ioMonDocsConfig(channelBase),
                        docsTokensCss = metacraftDocsTokensCss(),
                        clientEntry = "src/main.nim")
  echo "SSG: rendered ", n, " static pages into ./public/",
    (if channelBase.len > 0: " (hosted under " & channelBase & ")" else: "")
