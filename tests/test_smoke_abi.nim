# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest



import libsodium/libsodium_abi
test "init":
  echo randombytes_random()

converter toSeqOfBytes(s: string): seq[cuchar] =
  result = newSeq[cuchar](s.len)
  copyMem(addr result[0], addr s[0], s.len)
  

test "authenticated encryption":
  var key : array[32,cuchar]
  var nonce : array[24,cuchar]  
  let MESSAGE = "Hello, world!".toSeqOfBytes
  let CIPHERTEXT_LEN = (crypto_secretbox_MACBYTES + MESSAGE.len.uint)
  var ciphertext = newSeq[cuchar](CIPHERTEXT_LEN)

  crypto_secretbox_keygen(key)
  randombytes_buf(addr nonce, sizeof(nonce).uint)
  check crypto_secretbox_easy(addr ciphertext[0], addr MESSAGE[0], MESSAGE.len.uint, addr nonce[0], addr key[0]) == 0

  var decrypted = newSeq[cuchar](MESSAGE.len)

  check crypto_secretbox_open_easy(addr decrypted[0], addr ciphertext[0], CIPHERTEXT_LEN, addr nonce[0], addr key[0]) == 0
  
  check MESSAGE == decrypted





