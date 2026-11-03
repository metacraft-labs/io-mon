## The C `#include` of `exec_image_injectability.h`, for the two modules that
## compile it in: the consumer binding (`exec_image_injectability.nim`) and
## the shim runtime (`hooks/linux_preload_runtime.nim`).
##
## WHY THE DIGEST. Nim decides whether to recompile a module's C file from
## the C text it generates, and knows nothing of a header that text merely
## `#include`s. A bare include therefore keeps a stale object file after an
## edit to the header alone: measured while changing the classifier, the
## consumer kept the old verdicts while the shim (whose own .nim had also
## changed) got the new ones. Folding a digest of the header into the emitted
## text makes every header edit change the C file of each includer, so both
## are recompiled together.

import std/[hashes, os]

const
  execImageHeaderPath* = currentSourcePath().parentDir() /
    "exec_image_injectability.h"
  execImageIncludeDirective* =
    "/* exec_image_injectability.h digest " &
      $hash(staticRead(execImageHeaderPath)) & " */\n" &
    "#include \"" & execImageHeaderPath & "\"\n"
    ## Emit this (`{.emit: execImageIncludeDirective.}`) instead of a bare
    ## `#include`.
