# SPDX-FileCopyrightText: 2026 Metacraft Labs / Schelling Point Labs
# SPDX-License-Identifier: Apache-2.0
## io-mon docs -- thin SSR entry.

when defined(js):
  {.error: "ssr.nim is a C-target (server-side) entry point".}

import "../../../../isonim-docs/src/ssr" as frameworkSsr
import ./docs_config

proc renderRoute*(path: string; contentDir = "content"): tuple[status: int, html: string] =
  frameworkSsr.renderRoute(path, contentDir, cfg = ioMonDocsConfig())

when isMainModule:
  let (status, html) = renderRoute("/")
  echo "SSR smoke: GET / -> ", status, " (", html.len, " bytes)"
