# Package

version       = "1.0.18.0"
author        = "Geoffrey Picron"
description   = "Nim low level binding to libsodium"
license       = "(MIT OR Apache-2.0)"
srcDir        = "src"


# Dependencies

requires "nim >= 1.6.12"
requires "nimterop >= 0.6.13"


# Build
task updateWrapper, "Compile to pure JS":
    exec "nim c -r -o:./tmp/generate  src/libsodium/private/generate.nim"

before install:
  updateWrapperTask()

proc runBrowserWasmTest(test: string) =
  exec "nim c -d:emscripten -d:debug --threads:off --passL:'--emrun' -o:build/browser/" & test & ".html tests/" & test & ".nim"
  exec "emrun --browser=chrome --kill_exit --browser_args='--headless  --remote-debugging-port=0 --disable-gpu --disable-software-rasterizer' build/browser/" & test & ".html"

proc runNodeJsWasmTest(test: string) =
  exec "nim c -d:emscripten -d:debug --threads:off --passL:'--emrun' -o:build/nodejs/" & test & ".js tests/" & test & ".nim"
  exec "node  build/nodejs/" & test & ".js"

proc runNativeTest(test: string) =
  exec "nim c -d:debug --threads:off -o:build/native/" & test & " tests/" & test & ".nim"
  exec "build/native/" & test

import std/[os, strutils]

task test, "Run tests in the all supported environments":
  for test in listFiles("tests"):
    if test.extractFilename.startsWith("test") and test.endsWith(".nim"):
      let name = test.extractFilename.replace(".nim", "")
      runNativeTest(name)
      runNodeJsWasmTest(name)
      runBrowserWasmTest(name)
