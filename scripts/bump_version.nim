import std/[os, strutils, parseutils]

proc main() =
  let args = commandLineParams()
  if args.len != 1:
    echo "Usage: nim r scripts/bump_version.nim <major|minor|patch|version-string>"
    quit(1)

  let input = args[0]
  let versionFile = "version.txt"
  if not fileExists(versionFile):
    echo "Error: version.txt not found"
    quit(1)

  let currentVersion = readFile(versionFile).strip()
  var parts = currentVersion.split('.')
  if parts.len != 3:
    echo "Error: version.txt must contain a valid semver: " & currentVersion
    quit(1)

  var major, minor, patch: int
  discard parseInt(parts[0], major)
  discard parseInt(parts[1], minor)
  discard parseInt(parts[2], patch)

  var nextVersion = ""
  if input == "major":
    nextVersion = $(major + 1) & ".0.0"
  elif input == "minor":
    nextVersion = $major & "." & $(minor + 1) & ".0"
  elif input == "patch":
    nextVersion = $major & "." & $minor & "." & $(patch + 1)
  else:
    # Treat as literal version string
    nextVersion = input

  writeFile(versionFile, nextVersion & "\n")
  echo "Bumped version: ", currentVersion, " -> ", nextVersion

main()
