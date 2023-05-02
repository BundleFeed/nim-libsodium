# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

## Generic Hashing (blake2b)

import libsodium_abi
import private/utils
import common
import std/macros
import strutils

defineByteArrayType(GenericHash, crypto_generichash_BYTES)
defineByteArrayType(GenericHashKey, crypto_generichash_KEYBYTES)

func genericHashKeyGen*() : GenericHashKey = 
    crypto_generichash_keygen(result)

func genericHash*(msg: Message, key: GenericHashKey): GenericHash =
  checkRc crypto_generichash(result.address, result.len.uint, msg.address, msg.msgLen.uint, key.address, key.len.uint)

func genericHash*(msg: Message): GenericHash =
  checkRc crypto_generichash(result.address, result.len.uint, msg.address, msg.msgLen.uint, nil, 0.uint)

func genericHash[M:Message,O:Message]*(msg: Message, hash: var Message) =
  checkRc crypto_generichash(hash.address, hash.msgLen.uint, msg.address, msg.msgLen.uint, nil, 0.uint)

func genericHash[M:Message,O:Message]*(msg: Message, key: GenericHashKey, hash: var Message) =
  checkRc crypto_generichash(hash.address, hash.msgLen.uint, msg.address, msg.msgLen.uint, key.address, key.len.uint)


type GenericHashBuilder* = object
  state: crypto_generichash_state

func newGenericHashBuilder*(key: GenericHashKey): GenericHashBuilder =
  checkRc crypto_generichash_init(result.state.addr, key.address, key.len, crypto_generichash_BYTES)
  
func newGenericHashBuilder*(): GenericHashBuilder =
  checkRc crypto_generichash_init(result.state.addr, nil, 0.uint, crypto_generichash_BYTES)

func add*(builder: var GenericHashBuilder, msg: Message) =
  checkRc crypto_generichash_update(builder.state.addr, msg.address, msg.msgLen.uint)

func finish*(builder: var GenericHashBuilder): GenericHash =
  checkRc crypto_generichash_final(builder.state.addr, result.address, result.len.uint)

## SHA-2 (sha256, sha512)

defineByteArrayType(Sha256Hash, crypto_hash_sha256_BYTES)
defineByteArrayType(Sha512Hash, crypto_hash_sha512_BYTES)

macro generateElementFor(name) : untyped =
  let sodiumFuncName = newIdentNode( "crypto_hash_" & $name )
  let exportedName = newIdentNode($name & "Hash")
  let exportedNameType = newIdentNode(capitalizeAscii($name) & "Hash")
  let builderType = newIdentNode(capitalizeAscii($name) & "HashBuilder")
  let hashStateStruct = newIdentNode($sodiumFuncName & "_state")
  let builderConstructor = newIdentNode("new" & capitalizeAscii($name) & "HashBuilder")
  let sodiumBuilderInit = newIdentNode($sodiumFuncName & "_init")
  let sodiumBuilderUpdate = newIdentNode($sodiumFuncName & "_update")
  let sodiumBuilderFinal = newIdentNode($sodiumFuncName & "_final")

  result = newStmtList()
    
  result.add quote do:
    func `exportedName`*(msg: Message): `exportedNameType` =
      checkRc `sodiumFuncName`(result.address, msg.address, msg.msgLen.uint)

    type `builderType`* = object
      state: `hashStateStruct`

    func `builderConstructor`*(): `builderType` =
      checkRc `sodiumBuilderInit`(result.state.addr)
    
    func add*(builder: var `builderType`, msg: Message) =
      checkRc `sodiumBuilderUpdate`(builder.state.addr, msg.address, msg.msgLen.uint)
    
    func finish*(builder: var `builderType`): `exportedNameType` =
      checkRc `sodiumBuilderFinal`(builder.state.addr, result.address)
    

generateElementFor("sha256")
generateElementFor("sha512")



