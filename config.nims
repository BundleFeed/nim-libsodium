# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

switch("nimcache","./build/native")

if defined(emscripten):
  # This path will only run if -d:emscripten is passed to nim.
  switch("nimcache","./build/emscripten")

  --os:linux # Emscripten pretends to be linux.
  --cpu:wasm32 # Emscripten is 32bits.
  --cc:clang # Emscripten is very close to clang, so we ill replace it.
  when defined(windows):
    --clang.exe:emcc.bat  # Replace C
    --clang.linkerexe:emcc.bat # Replace C linker
    --clang.cpp.exe:emcc.bat # Replace C++
    --clang.cpp.linkerexe:emcc.bat # Replace C++ linker.
  else:
    --clang.exe:emcc  # Replace C
    --clang.linkerexe:emcc # Replace C linker
    --clang.cpp.exe:emcc # Replace C++
    --clang.cpp.linkerexe:emcc # Replace C++ linker.
  when compileOption("threads"):
    # We can have a pool size to populate and be available on page run
    # --passL:"-sPTHREAD_POOL_SIZE=2"
    discard
  --listCmd # List what commands we are running so that we can debug them.

  --gc:orc # GC:arc is friendlier with crazy platforms.
  --define:noSignalHandler # Emscripten doesn't support signal handlers.
  --passC:"-sSTACK_SIZE=1048576"
  --passL:"-sSTACK_SIZE=1048576"
  --passC:"-g3" # Debugging symbols.
  --passL:"-g3" # Debugging symbols.

