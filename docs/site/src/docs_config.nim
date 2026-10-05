# SPDX-FileCopyrightText: 2026 Metacraft Labs / Schelling Point Labs
# SPDX-License-Identifier: Apache-2.0
## io-mon docs -- this site's own `DocsConfig`.

import core/config
import core/base_path

const docsSiteOrigin* = "https://metacraft-labs.github.io/io-mon"

proc ioMonDocsConfig*(basePath = "/io-mon"): DocsConfig =
  let base = normalizeBasePath(basePath)
  DocsConfig(
    siteTitle: "io-mon docs",
    siteDescription: "Documentation for io-mon -- cross-platform filesystem and process monitoring library and CLI.",
    defaultRoute: "/",
    stylesheetHref: "/assets/style.css",
    baseUrl: docsSiteOrigin & (if base == "/": "" else: base),
    basePath: base,
    sectionOrder: @["getting_started", "guides", "reference"],
    footerHtml: "Built by <a href=\"https://github.com/metacraft-labs\">metacraft-labs</a>",
    appScriptHref: defaultAppScriptUrl,
    expandAllNavSections: true,
    headerLinks: @[
      (label: "GitHub", href: "https://github.com/metacraft-labs/io-mon"),
    ],
    sidebarLinks: @[
      (label: "Github", href: "https://github.com/metacraft-labs/io-mon",
       icon: "/assets/img/icon__github.svg"),
    ],
    sidebarThemeToggle: true,
    needHelp: (
      heading: "Need some help?",
      links: @[
        (label: "Open an issue", href: "https://github.com/metacraft-labs/io-mon/issues",
         icon: "/assets/img/icon__support.svg"),
        (label: "CLI Reference", href: "/reference/cli-reference",
         icon: "/assets/img/icon__faq.svg"),
      ],
    ),
  )
