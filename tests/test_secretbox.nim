# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/secretbox
import libsodium/random
import sequtils
import unittest

test "secret box easy":
  let key = secretBoxKeyGen()
  let message = "Hello"
  # 24 bytes
  let nonce = fromHex(SecretBoxNonce, "0001020304060708090a0b0c0d0e0f101112131415161718")
  let encrypted = secretBoxEncrypt(message, nonce, key)
  let decrypted = secretBoxDecrypt(encrypted, nonce, key)

  check toSeq(message.toOpenArrayByte(0, message.len - 1)) == decrypted


  
