# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/auth
import libsodium/random
import libsodium/common
import sequtils
import unittest

type MyArray = distinct array[10, byte]

test "a type that distinct Array":
  
  
  let authKey = authKeyGen()
  let message = MyArray([1.byte, 2, 3, 4, 5, 6, 7, 8, 9, 10])  

  let authMac = auth(message, authKey)
  check authVerify(authMac, message, authKey)
