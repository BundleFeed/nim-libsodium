# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium/signature
import libsodium/random
import sequtils
import unittest

test "boxed signature":
  let (pubKAlice, privKAlice) = signKeyGen()
  let message = "Hello"
  let signed = signedBox(message, privKAlice)
  let verified = openSignedBox(signed, pubKAlice)

  check verified == toSeq(message.toOpenArrayByte(0, message.len - 1))
  

test "detached signature":
  let (pubKAlice, privKAlice) = signKeyGen()
  let message = "Hello"
  let signature = detachedSign(message, privKAlice)
  
  check verifyDetachedSign(message, signature, pubKAlice) == true

  var randomSignature : SignSignature
  randomBytes(randomSignature)
  check verifyDetachedSign(message, randomSignature, pubKAlice) == false

test "multipart":
  let (pubKAlice, privKAlice) = signKeyGen()
  let (pubKBob, _) = signKeyGen()
  var randomSignature : SignSignature
  randomBytes(randomSignature)
  

  var builder = newSignBuilder(privKAlice)
  builder.add("Hello")
  builder.add(" ")
  builder.add("World")

  let signature = builder.finish()

  var verifier = newSignVerifier(pubKAlice, signature)
  verifier.add("Hello")
  verifier.add(" ")
  verifier.add("World")

  check verifier.finish() == true

  verifier = newSignVerifier(pubKBob, signature)
  verifier.add("Hello World")

  check verifier.finish() == false # must be created exactly the same parts

  verifier = newSignVerifier(pubKBob, signature)
  verifier.add("Hello")
  verifier.add(" ")
  verifier.add("World")

  check verifier.finish() == false

  verifier = newSignVerifier(pubKBob, randomSignature)
  verifier.add("Hello")
  verifier.add(" ")
  verifier.add("World")

  check verifier.finish() == false

