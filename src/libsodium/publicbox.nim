# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

## Public-key authenticated encryption.  (aka "crypto_secretbox")
## This is a high-level API for libsodium's crypto_box_* functions.
## 
## See: https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption

import libsodium_abi
import private/utils
import common

defineByteArrayType(BoxPublicKey, crypto_box_PUBLICKEYBYTES)
defineByteArrayType(BoxPrivateKey, crypto_box_SECRETKEYBYTES)
defineByteArrayType(BoxNonce, crypto_box_NONCEBYTES)
defineByteArrayType(BoxMac, crypto_box_MACBYTES)

template boxLen*(source: Message) : uint = msgLen(source).uint + crypto_box_MACBYTES
    

func boxKeyGen*() : (BoxPublicKey, BoxPrivateKey) =
  checkRc crypto_box_keypair(result[0].address, result[1].address)

func boxEncrypt*(message: Message, nonce: BoxNonce, recipientPublicKey: BoxPublicKey, senderPrivateKey: BoxPrivateKey) : seq[byte] =
  result = newSeq[byte](message.boxLen)
  checkRc crypto_box_easy(result.address, message.address, message.msgLen.uint64, nonce.address, recipientPublicKey.address, senderPrivateKey.address)

func boxDecrypt*(ciphertext: Message, nonce: BoxNonce, senderPublicKey: BoxPublicKey, recipientPrivateKey: BoxPrivateKey) : seq[byte] =
  result = newSeq[byte](ciphertext.msgLen - crypto_box_MACBYTES.int)
  checkRc crypto_box_open_easy(result.address, ciphertext.address, ciphertext.msgLen.uint64, nonce.address, senderPublicKey.address, recipientPrivateKey.address)