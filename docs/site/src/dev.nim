# SPDX-FileCopyrightText: 2026 Metacraft Labs / Schelling Point Labs
# SPDX-License-Identifier: Apache-2.0
## Live-reloading dev server for io-mon docs.
##
## Serves this site's own `content/` plus its themed assets (`assets/style.css`
## with the Metacraft token CSS prepended, and the `static/` tree -- the same
## dirs `build.nim` maps into `public/assets/`) over HTTP, and watches
## `content/` so any edit hot-reloads every open tab via the framework's
## `dev_server` WebSocket live-reload channel.

import std/[os, strutils, asyncdispatch]
import docs_scaffold
import ./docs_config
import ./theme_tokens

export docs_scaffold

proc newDocsDevServer*(contentDir = "content";
                       assetsDirs = @["assets", "static"]): DevServer =
  docsDevServer(ioMonDocsConfig("/"), contentDir = contentDir, assetsDirs = assetsDirs,
                tokensCssProvider = (proc(): string = docsTokensCssLive()),
                watchPaths = @[docsDesignSystemPath],
                clientEntry = "src/main.nim")

when isMainModule:
  let port = if paramCount() >= 1: parseInt(paramStr(1)) else: 8000
  let host =
    if paramCount() >= 2: paramStr(2)
    elif existsEnv("AH_DEV_HOST"): getEnv("AH_DEV_HOST")
    else: "127.0.0.1"
  let server = newDocsDevServer()
  stdout.writeLine "io-mon docs dev server -> http://" & host & ":" & $port &
    "  (watching content/ + shared design system, live reload on; Ctrl-C to stop)"
  stdout.flushFile()
  waitFor serve(server, port, host = host)
