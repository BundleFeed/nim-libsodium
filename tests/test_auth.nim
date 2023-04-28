# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/auth
import libsodium/random
import sequtils
import unittest

test "auth":
  let authKey = authKeyGen()
  let message = "Hello"

  let authMac = auth(message, authKey)
  check authVerify(authMac, message, authKey)
