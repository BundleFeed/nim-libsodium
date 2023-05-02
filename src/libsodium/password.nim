# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

## Password hashing functions
## ==========================
## This module contains functions to hash passwords and check if a password
## matches a hash.
## see https://libsodium.gitbook.io/doc/password_hashing/default_phf
## 

import libsodium_abi
import private/utils
import common

defineByteArrayType(PasswordHashSeed, crypto_pwhash_SALTBYTES)
defineByteArrayType(PasswordHashString, crypto_pwhash_STRBYTES)

type
  CpuLimit = enum
    cpuInteractive = crypto_pwhash_OPSLIMIT_INTERACTIVE,
    cpuModerate = crypto_pwhash_OPSLIMIT_MODERATE,
    cpuSensitive = crypto_pwhash_OPSLIMIT_SENSITIVE,
    cpuMax = crypto_pwhash_OPSLIMIT_MAX
  
  MemoryLimit = enum
    memInteractive = crypto_pwhash_MEMLIMIT_INTERACTIVE,
    memModerate = crypto_pwhash_MEMLIMIT_MODERATE,
    memSensitive = crypto_pwhash_MEMLIMIT_SENSITIVE,
    memMax = crypto_pwhash_MEMLIMIT_MAX
  
  Algorithm = enum
    algDefault 
    algArgon2i13 
    algArgon2id13 


converter algEnumToAbiInt(a: Algorithm): cint {.inline.} =
  case a
  of Algorithm.algDefault: libsodium_abi.crypto_pwhash_ALG_ARGON2ID13
  of Algorithm.algArgon2i13: libsodium_abi.crypto_pwhash_ALG_ARGON2I13
  of Algorithm.algArgon2id13: libsodium_abi.crypto_pwhash_ALG_ARGON2ID13

proc passwordHash*[P:Message, T](password: P, seed: PasswordHashSeed, target: var T,
  cpuLimit: CpuLimit = CpuLimit.cpuInteractive,
  memoryLimit: MemoryLimit = MemoryLimit.memInteractive, 
  algorithm: Algorithm = Algorithm.algDefault) =
  ## Hash a password
  ## Parameters:
  ## - `password`: the password to hash
  ## - `seed`: a random seed
  ## - `target`: the target buffer to store the hash
  ## - `cpuLimit`: the CPU limit to use
  ## - `memoryLimit`: the memory limit to use
  ## - `algorithm`: the algorithm to use
  
  checkRc crypto_pwhash(target.address, target.msgLen.uint64, cast[cstring](password.address), password.msgLen.uint64, seed.address, cpuLimit.uint, memoryLimit.uint, algorithm.algEnumToAbiInt)



