# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)
import nimterop/build/shell
import nimterop/cimport
import std/[os, strutils, pathnorm]


proc downloadAndConfigure*(buildDir: string) = 
  let sodiumExpandedDir = buildDir / "libsodium-stable"

  rmDir(sodiumExpandedDir)
  createDir(buildDir)

  downloadUrl("https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz", buildDir)

  echo "# Running configure"
  let (output, ret) = execAction("cd " & sodiumExpandedDir & " && ./configure")
  if ret != 0:
    raise newException(OSError, "Error running configure")

when isMainModule:
  assert paramCount() == 1, "Expected 1 argument, the install path"
  let installPath = paramStr(1)
  downloadAndConfigure(installPath)
