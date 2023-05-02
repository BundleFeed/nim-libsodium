# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/password
import libsodium/random
import sequtils
import unittest

test "key derivation":
  var seed : PasswordHashSeed
  randomBytes(seed)
  let password = "Correct Horse Battery Staple"

  var bytes = newSeq[uint8](16)
  passwordHash(password, seed, bytes)
  
  check bytes != @[0.uint8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

  var bytes2 = newSeq[uint8](16)
  passwordHash(password, seed, bytes2)
  
  check bytes == bytes2

  
  
