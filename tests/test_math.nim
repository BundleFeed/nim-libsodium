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
