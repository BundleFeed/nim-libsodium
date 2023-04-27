# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)
import ../common
import std/strutils

template defineByteArrayType*(typeName: untyped, size: Natural): untyped =
  type typeName* = distinct array[size, byte]
  

  template `[]`*(buf: typeName, i: int): byte = array[size, byte](buf)[i]
  template `[]=`*(buf: var typeName, i: int, v: byte) = array[size, byte](buf)[i]= v
  func fromHex*(T: typedesc[typeName], s: string): T = 
    let bytes = parseHexStr(s)
    if bytes.len.uint != size.uint:
      raise newException(ValueError, "Invalid length : " & $bytes.len & " != " & $size)
    copyMem(addr result[0], unsafeAddr bytes[0], size.uint)

  func toHex*(buf: typeName): string =
    result = newStringOfCap(size * 2)
    for i in 0 ..< size:
      result.add toHex(array[size, byte](buf)[i])
  
  template address*(buf: typeName) : ptr byte = unsafeAddr array[size, byte](buf)[0]
  template len*(buf: typeName): uint = size

  
  converter toUCharArray*(buf: typeName): array[size, cuchar] = cast[array[size, cuchar]](buf)

converter toPtrCUChar*(p: ptr byte): ptr cuchar = cast[ptr cuchar](p)

template checkRc*(call) =
  let ret = call
  if ret != 0:
    raise newException(SodiumError, "Failure to call libsodium")
    