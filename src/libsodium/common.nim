# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)
import std/typetraits

type
    SodiumError* = object of CatchableError 
    AnyArray*[N] = array[N,byte]
    AnyBuffer* = concept b, i
      distinctBase(b) is AnyArray[i]
    Message* = string | openArray[byte] | cstring | seq[byte] | seq[char] | AnyArray | AnyBuffer

template address*(m: Message): ptr byte = 
  cast[ptr byte](m.distinctBase[0].unsafeAddr)

template msgLen*(m: Message): int = 
  when distinctBase(m) is array: sizeof(m)
  else: m.len


