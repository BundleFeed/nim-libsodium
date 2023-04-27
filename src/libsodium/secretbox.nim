# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

## Secret-key authenticated encryption.  (aka "crypto_secretbox")
## This is a high-level API for libsodium's crypto_secretbox_* functions.
## 
## See https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox

import libsodium_abi
import private/utils
import common

defineByteArrayType(SecretBoxKey, crypto_secretbox_KEYBYTES)
defineByteArrayType(SecretBoxNonce, crypto_secretbox_NONCEBYTES)

func secretBoxKeyGen*() : SecretBoxKey = 
    crypto_secretbox_keygen(result)

template secretBoxLen*(source: Message) : uint = source.len.uint + crypto_secretbox_MACBYTES

func secretBoxEncrypt*(source: Message, nonce: SecretBoxNonce, key: SecretBoxKey, target: var Message) =
    doAssert target.len.uint == source.secretBoxLen
    checkRc crypto_secretbox_easy(addr target[0], addr source[0], source.len.culonglong, nonce.address, key.address)

func secretBoxEncrypt*(source: Message, nonce: SecretBoxNonce, key: SecretBoxKey) : seq[byte] =
    result.setLen(source.secretBoxLen)
    checkRc crypto_secretbox_easy(addr result[0], addr source[0], source.len.culonglong, nonce.address, key.address)

func secretBoxDecrypt*(source: Message, nonce: SecretBoxNonce, key: SecretBoxKey, target: var Message) =
    doAssert target.len.uint == source.len.uint - crypto_secretbox_MACBYTES
    checkRc crypto_secretbox_open_easy(addr target[0], addr source[0], source.len.culonglong, nonce.address, key.address)

func secretBoxDecrypt*(source: Message, nonce: SecretBoxNonce, key: SecretBoxKey) : seq[byte] =
    result.setLen(source.len.uint - crypto_secretbox_MACBYTES)
    checkRc crypto_secretbox_open_easy(addr result[0], addr source[0], source.len.culonglong, nonce.address, key.address)