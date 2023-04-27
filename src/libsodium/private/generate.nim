# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import nimterop/build/shell
import nimterop/cimport
import std/[os, strutils, pathnorm]

const projectDir = pathnorm.normalizePath(gorge("pwd") / ".." / ".." / "..")

echo "projectDir is ", projectDir

const buildDir = projectDir / "build/libsodium_abi"
const sodiumExpandedDir = buildDir / "libsodium-stable"

# this is relative to the current file
  
const sodiumSrcDir = sodiumExpandedDir / "src" / "libsodium"
const includeDir1 = sodiumSrcDir / "include"
const includeDir2 = includeDir1 / "sodium"


static: 
  rmDir(buildDir)
  createDir(buildDir)

  downloadUrl("https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz", buildDir)

  echo "# Running configure"
  let (output, ret) = execAction("cd " & sodiumExpandedDir & " && ./configure")
  if ret != 0:
    echo "Error running configure"
    echo output
    quit(1)


static:
  cDebug()


cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    
    case sym.kind
    of nskConst:
      echo sym.name
    of nskProc:
      for suffix in ["_keybytes", "_nsecbytes", "_npubbytes", "_bytes", "_abytes", "_primitive",
                     "_noncebytes", "_seedbytes", "_publickeybytes", "_secretkeybytes", "_beforenmbytes",
                     "_macbytes", "_statebytes", "_blockbytes", "_hashbytes", "_contextbytes",
                     "_boxzerobytes", "_zerobytes", "_outputbytes", "_inputbytes", "_constbytes",
                     "_bytes_min", "_bytes_max", "_keybytes_min", "_keybytes_max", "_saltbytes", "_personalbytes",
                     "_sessionkeybytes", "_alg_argon2i13", "_alg_argon2id13", "_passwd_min", "_passwd_max", "_opslimit_min",
                     "_opslimit_max", "_memlimit_min", "_memlimit_max", "_strbytes", "_strprefix",
                     "_opslimit_interactive", "_memlimit_interactive", "_opslimit_moderate",
                     "_memlimit_moderate", "_opslimit_sensitive", "_memlimit_sensitive", "_opslimit_min",
                     "_scalarbytes", "_tag_message", "_tag_push", "_tag_rekey", "_tag_final", "_sealbytes",
                     "_uniformbytes", "_nonreducedscalarbytes"
                      
                     ]:
        if sym.name.endsWith(suffix):
          sym.name = sym.name.substr(0,sym.name.len - suffix.len - 1) & "_CONSTANT" & suffix.toUpper
          break
      case sym.name
      of "_sodium_runtime_get_cpu_features" : sym.name = "INTERNAL_sodium_runtime_get_cpu_features"
      of "_sodium_alloc_init" : sym.name = "INTERNAL_sodium_alloc_init"

    of nskType:
      if sym.name[^1] == '_':
        sym.name = sym.name & "def"
      case sym.name
      of "cuchar": sym.name = "char"
      of "culong": sym.name = "uint32"
      of "culonglong": sym.name = "uint64"

    of nskField:
      case sym.name
      of "ctx_" : sym.name = "ctx"
      of "_pad" : sym.name = "INTERNAL_pad"
      of "b1_"  : sym.name = "b1"
      of "b2_"  : sym.name = "b2"

    else:
      discard




cIncludeDir(@[includeDir1, includeDir2])
#cIncludeDir(@["../libsodium-src/libsodium-stable/src/libsodium/include/sodium"])
cCompile(sodiumSrcDir)


cImport(includeDir1 / "sodium.h", recurse=true, flags="-H", nimfile= buildDir / "generated.nim")


echo "Generated binding for libsodium:", sodium_version_string()
