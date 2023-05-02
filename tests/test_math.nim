# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/publicbox
import libsodium/secretbox
import libsodium/math
import sequtils
import unittest

test "scalar multiplication":
  let (pk1,sk1) = boxKeyGen()
  let (pk2,sk2) = boxKeyGen()

  let shared1 = scalarMult(sk1, pk2)
  let shared2 = scalarMult(sk2, pk1)

  check shared1 == shared2

test "increment":
  var nonce  = newSeq[byte](10)
  increment(nonce)

  check nonce == @[1.byte, 0, 0, 0, 0, 0, 0, 0, 0, 0]

  for i in 0..255:
    increment(nonce)

  check nonce == @[1.byte, 1, 0, 0, 0, 0, 0, 0, 0, 0]

test "increment overflow wraps":
  var nonce = newSeq[byte](10)
  for e in nonce.mitems:
    e = 255.byte
  increment(nonce)

  check nonce == @[0.byte, 0, 0, 0, 0, 0, 0, 0, 0, 0]


