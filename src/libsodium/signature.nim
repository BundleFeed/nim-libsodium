# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)
import libsodium_abi
import private/utils
import common

defineByteArrayType(SignPublicKey, crypto_sign_PUBLICKEYBYTES)
defineByteArrayType(SignPrivateKey, crypto_sign_SECRETKEYBYTES)
defineByteArrayType(SignKeySeed, crypto_sign_SEEDBYTES)
defineByteArrayType(SignSignature, crypto_sign_BYTES)


func signKeyGen*() : (SignPublicKey, SignPrivateKey) =
  checkRc crypto_sign_keypair(result[0].address, result[1].address)

func signKeyGen*(seed: SignKeySeed) : (SignPublicKey, SignPrivateKey) =
  checkRc crypto_sign_seed_keypair(result[0].address, result[1].address, seed.address)

template signedBoxLen*(source: Message) : uint = source.len.uint + crypto_sign_BYTES

func signedBox*(source: Message, privateKey: SignPrivateKey) : seq[byte] =
  result.setLen(signedBoxLen(source))
  checkRc crypto_sign(result.address, nil, source.address, source.len.uint, privateKey.address)
  
func openSignedBox*(source: Message, publicKey: SignPublicKey) : seq[byte] =
  result.setLen(source.len.uint - crypto_sign_BYTES)
  checkRc crypto_sign_open(result.address, nil, source.address, source.len.uint, publicKey.address)

func detachedSign*(source: Message, privateKey: SignPrivateKey) : SignSignature =
  checkRc crypto_sign_detached(result.address, nil, source.address, source.len.uint, privateKey.address)

func verifyDetachedSign*(source: Message, signature: SignSignature, publicKey: SignPublicKey) : bool =
  crypto_sign_verify_detached(signature.address, source.address, source.len.uint, publicKey.address) == 0

type 
    SignBuilder* = object
      state: crypto_sign_state
      privateKey: SignPrivateKey
    SignVerifier* = object
      state: crypto_sign_state
      publicKey: SignPublicKey
      signature: SignSignature

func newSignBuilder*(privateKey: SignPrivateKey) : SignBuilder =
  result.privateKey = privateKey
  checkRc crypto_sign_init(result.state.addr)

func add*(builder: var SignBuilder, source: sink Message) =
  checkRc crypto_sign_update(builder.state.addr, source.address, source.len.uint)

func finish*(builder: var SignBuilder) : SignSignature =
  checkRc crypto_sign_final_create(builder.state.addr, result.address, nil, builder.privateKey.address)

func newSignVerifier*(publicKey: SignPublicKey, signature: SignSignature) : SignVerifier =
  result.publicKey = publicKey
  result.signature = signature
  checkRc crypto_sign_init(result.state.addr)

func add*(verifier: var SignVerifier, source: sink Message) =
  checkRc crypto_sign_update(verifier.state.addr, source.address, source.len.uint)

func finish*(verifier: var SignVerifier) : bool =
  crypto_sign_final_verify(verifier.state.addr, verifier.signature.address, verifier.publicKey.address) == 0

