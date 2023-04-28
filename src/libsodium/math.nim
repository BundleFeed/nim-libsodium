# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium_abi
import publicbox
import secretbox
import signature
import private/utils
import common

func scalarMult*(n: BoxPrivateKey, p: BoxPublicKey) : SecretBoxKey {.inline.} =
    ## Computes a scalar multiplication
    ## https://download.libsodium.org/doc/advanced/scalar_multiplication
    
    check_rc crypto_scalarmult(result.address, n.address, p.address)

func signKeyToBoxKey*(pk: SignPublicKey) : BoxPublicKey {.inline.} =
    ## Converts a sign public key to a box public key
    ## https://download.libsodium.org/doc/advanced/ed25519-curve25519
    
    check_rc crypto_sign_ed25519_pk_to_curve25519(result.address, pk.address)

func signKeyToBoxKey*(sk: SignPrivateKey) : BoxPrivateKey {.inline.} =
    ## Converts a sign secret key to a box secret key
    ## https://download.libsodium.org/doc/advanced/ed25519-curve25519
    
    check_rc crypto_sign_ed25519_sk_to_curve25519(result.address, sk.address)
