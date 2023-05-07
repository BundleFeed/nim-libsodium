# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium_abi
import private/utils

defineByteArrayType(RandomBytesSeed, randombytes_SEEDBYTES)


func randomBytes*[Buffer](buffer: var Buffer) {.inline.} =
  randombytes_buf(addr buffer[0], buffer.len.uint)

func randomBytes*[Buffer](buffer: var Buffer, seed: RandomBytesSeed)  {.inline.} =
  randombytes_buf_deterministic(addr buffer[0], buffer.len.uint, seed)

func randomUniform*(upperBound: uint32): uint32 {.inline.} =
  ## upperBound is exclude in the range
  randombytes_uniform(upperBound)