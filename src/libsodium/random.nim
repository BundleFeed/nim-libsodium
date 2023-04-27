# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import libsodium_abi
import private/utils

defineByteArrayType(RandomBytesSeed, randombytes_SEEDBYTES)


template randomBytes*[Buffer](buffer: var Buffer) =
  randombytes_buf(addr buffer[0], buffer.len.uint)

template randomBytes*[Buffer](buffer: var Buffer, seed: RandomBytesSeed) =
  randombytes_buf_deterministic(addr buffer[0], buffer.len.uint, seed)