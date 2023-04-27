# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

type
    SodiumError* = object of CatchableError 
    Message* = string | openArray[byte] | cstring | seq[byte] | seq[char]

template address*(m: Message): ptr byte = cast[ptr byte](m[0].unsafeAddr)
