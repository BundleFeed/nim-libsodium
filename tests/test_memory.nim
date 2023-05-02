# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/memory
import libsodium/random
import libsodium/math
import sequtils
import unittest


test "zeroing memory":
  var buffer = newSeq[byte](50)
  randomBytes(buffer)

  check buffer != newSeq[byte](50)

  zeroMemory(buffer)

  check buffer == newSeq[byte](50)

test "memory locking":
  var buffer = newSeq[byte](50)
  randomBytes(buffer)

  check buffer != newSeq[byte](50)

  lockMemory(buffer)

  unlockMemory(buffer)
