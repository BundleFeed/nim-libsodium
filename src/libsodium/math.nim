# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium_abi
import publicbox
import secretbox
import private/utils
import common

func scalarMult*(n: BoxPrivateKey, p: BoxPublicKey) : SecretBoxKey {.inline.} =
    ## Computes a scalar multiplication
    ## https://download.libsodium.org/doc/advanced/scalar_multiplication
    
    check_rc crypto_scalarmult(result.address, n.address, p.address)
