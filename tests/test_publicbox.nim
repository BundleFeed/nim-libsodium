# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/publicbox
import libsodium/random
import sequtils
import unittest

test "public box easy":
  let (pubKAlice, privKAlice) = boxKeyGen()
  let (pubKBob, privKBob) = boxKeyGen()
  let message = "Hello"
  var nonce : BoxNonce
  randomBytes(nonce)
  let cipher = boxEncrypt(message, nonce, pubKBob, privKAlice)
  let decrypted = boxDecrypt(cipher, nonce, pubKAlice, privKBob)

  check decrypted == toSeq(message.toOpenArrayByte(0, message.len - 1))
  
