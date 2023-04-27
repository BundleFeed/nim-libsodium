# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/random
import unittest

test "generating buffer":
  var buffer = newSeq[byte](50)
  randomBytes(buffer)

test "generation buffer from seed":
  var buffer = newSeq[byte](10)
  let seed = fromHex(RandomBytesSeed, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  randomBytes(buffer, seed)

  check buffer == @[13.byte, 142, 108, 198, 135, 21, 100, 137, 38, 115]