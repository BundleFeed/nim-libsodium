# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

## This module contains the libsodium memory functions
## https://libsodium.gitbook.io/doc/memory_management
## 

import libsodium_abi
import private/utils
import common

when defined(posix):
  import std/posix_utils

proc zeroMemory*(p: pointer, size: int) {.inline.} =
    libsodium_abi.sodium_memzero(p, size.uint)

proc zeroMemory*(message: var Message) {.inline.} =
    libsodium_abi.sodium_memzero(message.address, message.msgLen.uint)

proc lockMemory*(message: var Message) {.inline.} =
    when defined(posix):
        memoryLock(message.address, message.msgLen.int)
    else:
        check_rc libsodium_abi.sodium_mlock(message.address, message.msgLen.uint)

proc unlockMemory*(message: var Message) {.inline.} =
    when defined(posix):
        memoryUnlock(message.address, message.msgLen.int)
    else:
        check_rc libsodium_abi.sodium_munlock(message.address, message.msgLen.uint)

proc constantTimeMemCmp(a: pointer, b: pointer, size: int): bool {.inline.} =
    libsodium_abi.sodium_memcmp(a, b, size.uint) == 0

proc constantTimeMemCmp(a: Message, b: Message): bool {.inline.} =
    assert a.msgLen == b.msgLen
    libsodium_abi.sodium_memcmp(a.address, b.address, a.msgLen.uint) == 0




type 
  ProtectedBuffer* = object
    len, cap: uint
    data: ptr UncheckedArray[byte]

proc `=destroy`*(x: var ProtectedBuffer) =
  if x.data != nil:
    libsodium_abi.sodium_free(x.data)


proc `=copy`*(a: var ProtectedBuffer; b: ProtectedBuffer) =
  # do nothing for self-assignments:
  if a.data == b.data: return
  `=destroy`(a)
  wasMoved(a)
  a.len = b.len
  a.cap = b.cap
  if b.data != nil:
    a.data = cast[ptr UncheckedArray[byte]](libsodium_abi.sodium_malloc(b.cap.uint))
    for i in 0..<a.len:
      a.data[i] = b.data[i]

proc `=sink`*(a: var ProtectedBuffer; b: ProtectedBuffer) =
  # move assignment, optional.
  # Compiler is using `=destroy` and `copyMem` when not provided
  `=destroy`(a)
  wasMoved(a)
  a.len = b.len
  a.cap = b.cap
  a.data = b.data

proc add*(x: var ProtectedBuffer; y: sink byte) =
  if x.len >= x.cap:
    x.cap = max(x.len + 1, x.cap * 2)
    var newData = libsodium_abi.sodium_malloc(x.cap.uint)
    copyMem(newData, x.data, x.len)
    libsodium_abi.sodium_free(x.data)
    x.data = cast[ptr UncheckedArray[byte]](newData)
  x.data[x.len] = y
  inc x.len

proc `[]`*(x: ProtectedBuffer; i: Natural): lent byte =
  assert i.uint < x.len
  x.data[i]

proc `[]=`*(x: var ProtectedBuffer; i: Natural; y: sink byte) =
  assert i.uint < x.len
  x.data[i] = y

proc newBufferOfCap*[T](capacity: uint): ProtectedBuffer =
  # capacity is aligned to 16 bytes
  result.cap = (capacity + 15) and not 15
  result.len = 0
  result.data = cast[ptr UncheckedArray[byte]](libsodium_abi.sodium_malloc(capacity.uint))
  

proc len*(x: ProtectedBuffer): int {.inline.} = x.len.int
proc cap*(x: ProtectedBuffer): int {.inline.} = x.cap.int
