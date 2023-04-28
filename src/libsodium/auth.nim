# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium_abi
import private/utils
import common

defineByteArrayType(AuthMac, crypto_auth_BYTES)
defineByteArrayType(AuthKey, crypto_auth_KEYBYTES)


func authKeyGen*() : AuthKey {.inline.} =
    ## Generates a random authentication key
    
    crypto_auth_keygen(result)

func auth*(msg: Message, key: AuthKey) : AuthMac {.inline.} =
    ## Computes an authentication tag for a message
    
    checkRc crypto_auth(result.address, msg.address, msg.msgLen.uint64, key.address)

func authVerify*(mac: AuthMac, msg: Message, key: AuthKey) : bool {.inline.} =
    ## Verifies an authentication tag for a message
    
    crypto_auth_verify(mac.address, msg.address, msg.msgLen.uint64, key.address) == 0

