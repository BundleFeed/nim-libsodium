import ../libsodium_abi/generated


export generated

var initialized = false
if not initialized:
  if sodium_init() != 0:
    raise newException(Defect, "Failed to initialize libsodium")
  initialized = true

func SODIUM_MIN[T](a, b: T): T = 
  if (a < b): 
    a 
  else: 
    b
const SODIUM_SIZE_MAX = SODIUM_MIN(high(uint64), high(uint))
const SIZE_MAX = high(uint)

const crypto_aead_aes256gcm_MESSAGEBYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_aes256gcm_ABYTES, (16.uint64 * ((1.uint64 shl 32) - 2.uint64)))
const crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_IETF_ABYTES, (64.uint64 * ((1.uint64 shl 32) - 1.uint64)))
const crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX* = (SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES)

const crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX* = (SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_IETF_ABYTES)




const crypto_auth_BYTES* = crypto_auth_hmacsha512256_BYTES
const crypto_auth_KEYBYTES* = crypto_auth_hmacsha512256_KEYBYTES
const crypto_stream_xsalsa20_MESSAGEBYTES_MAX* = SODIUM_SIZE_MAX
const crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX* = (crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_box_curve25519xsalsa20poly1305_MACBYTES)
const crypto_box_SEEDBYTES* = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
const crypto_box_PUBLICKEYBYTES* = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
const crypto_box_SECRETKEYBYTES* = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
const crypto_box_NONCEBYTES* = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
const crypto_box_MACBYTES* = crypto_box_curve25519xsalsa20poly1305_MACBYTES
const crypto_box_MESSAGEBYTES_MAX* = crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX
const crypto_box_BEFORENMBYTES* = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
const crypto_box_SEALBYTES* = (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
const crypto_box_ZEROBYTES* = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
const crypto_box_BOXZEROBYTES* = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
const crypto_generichash_BYTES_MIN* = crypto_generichash_blake2b_BYTES_MIN
const crypto_generichash_BYTES_MAX* = crypto_generichash_blake2b_BYTES_MAX
const crypto_generichash_BYTES* = crypto_generichash_blake2b_BYTES
const crypto_generichash_KEYBYTES_MIN* = crypto_generichash_blake2b_KEYBYTES_MIN
const crypto_generichash_KEYBYTES_MAX* = crypto_generichash_blake2b_KEYBYTES_MAX
const crypto_generichash_KEYBYTES* = crypto_generichash_blake2b_KEYBYTES
const crypto_hash_BYTES* = crypto_hash_sha512_BYTES
const crypto_kdf_BYTES_MIN* = crypto_kdf_blake2b_BYTES_MIN
const crypto_kdf_BYTES_MAX* = crypto_kdf_blake2b_BYTES_MAX
const crypto_kdf_CONTEXTBYTES* = crypto_kdf_blake2b_CONTEXTBYTES
const crypto_kdf_KEYBYTES* = crypto_kdf_blake2b_KEYBYTES
const crypto_onetimeauth_BYTES* = crypto_onetimeauth_poly1305_BYTES
const crypto_onetimeauth_KEYBYTES* = crypto_onetimeauth_poly1305_KEYBYTES
const crypto_pwhash_argon2i_BYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX, 4294967295U)
const crypto_pwhash_argon2i_MEMLIMIT_MAX* = (if (SIZE_MAX >= 4398046510080u): 4398046510080u elif (SIZE_MAX >= 2147483648u): 2147483648u else: 32768u)
const crypto_pwhash_argon2id_BYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX, 4294967295u)
const crypto_pwhash_argon2id_MEMLIMIT_MAX* = (if (SIZE_MAX >= 4398046510080u): 4398046510080u elif (SIZE_MAX >= 2147483648u): 2147483648u else: 32768u)
const crypto_pwhash_ALG_ARGON2I13* = crypto_pwhash_argon2i_ALG_ARGON2I13
const crypto_pwhash_ALG_ARGON2ID13* = crypto_pwhash_argon2id_ALG_ARGON2ID13
const crypto_pwhash_ALG_DEFAULT* = crypto_pwhash_ALG_ARGON2ID13
const crypto_pwhash_BYTES_MIN* = crypto_pwhash_argon2id_BYTES_MIN
const crypto_pwhash_BYTES_MAX* = crypto_pwhash_argon2id_BYTES_MAX
const crypto_pwhash_PASSWD_MIN* = crypto_pwhash_argon2id_PASSWD_MIN
const crypto_pwhash_PASSWD_MAX* = crypto_pwhash_argon2id_PASSWD_MAX
const crypto_pwhash_SALTBYTES* = crypto_pwhash_argon2id_SALTBYTES
const crypto_pwhash_STRBYTES* = crypto_pwhash_argon2id_STRBYTES
const crypto_pwhash_STRPREFIX* = crypto_pwhash_argon2id_STRPREFIX
const crypto_pwhash_OPSLIMIT_MIN* = crypto_pwhash_argon2id_OPSLIMIT_MIN
const crypto_pwhash_OPSLIMIT_MAX* = crypto_pwhash_argon2id_OPSLIMIT_MAX
const crypto_pwhash_MEMLIMIT_MIN* = crypto_pwhash_argon2id_MEMLIMIT_MIN
const crypto_pwhash_MEMLIMIT_MAX* = crypto_pwhash_argon2id_MEMLIMIT_MAX
const crypto_pwhash_OPSLIMIT_INTERACTIVE* = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
const crypto_pwhash_MEMLIMIT_INTERACTIVE* = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
const crypto_pwhash_OPSLIMIT_MODERATE* = crypto_pwhash_argon2id_OPSLIMIT_MODERATE
const crypto_pwhash_MEMLIMIT_MODERATE* = crypto_pwhash_argon2id_MEMLIMIT_MODERATE
const crypto_pwhash_OPSLIMIT_SENSITIVE* = crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
const crypto_pwhash_MEMLIMIT_SENSITIVE* = crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
const crypto_scalarmult_BYTES* = crypto_scalarmult_curve25519_BYTES
const crypto_scalarmult_SCALARBYTES* = crypto_scalarmult_curve25519_SCALARBYTES
const crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX* = (crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_secretbox_xsalsa20poly1305_MACBYTES)
const crypto_secretbox_KEYBYTES* = crypto_secretbox_xsalsa20poly1305_KEYBYTES
const crypto_secretbox_NONCEBYTES* = crypto_secretbox_xsalsa20poly1305_NONCEBYTES
const crypto_secretbox_MACBYTES* = crypto_secretbox_xsalsa20poly1305_MACBYTES
const crypto_secretbox_MESSAGEBYTES_MAX* = crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX
const crypto_secretbox_ZEROBYTES* = crypto_secretbox_xsalsa20poly1305_ZEROBYTES
const crypto_secretbox_BOXZEROBYTES* = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
const crypto_stream_chacha20_MESSAGEBYTES_MAX* = SODIUM_SIZE_MAX
const crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX, 64.uint64 * (1.uint64 shl 32))
const crypto_secretstream_xchacha20poly1305_HEADERBYTES* = crypto_aead_xchacha20poly1305_IETF_NPUBBYTES
const crypto_secretstream_xchacha20poly1305_KEYBYTES* = crypto_aead_xchacha20poly1305_IETF_KEYBYTES
const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX - crypto_secretstream_xchacha20poly1305_ABYTES, (64.uint64 * ((1.uint64 shl 32) - 2.uint64)))
const crypto_shorthash_BYTES* = crypto_shorthash_siphash24_BYTES
const crypto_shorthash_KEYBYTES* = crypto_shorthash_siphash24_KEYBYTES
const crypto_sign_ed25519_MESSAGEBYTES_MAX* = (SODIUM_SIZE_MAX - crypto_sign_ed25519_BYTES)
const crypto_sign_BYTES* = crypto_sign_ed25519_BYTES
const crypto_sign_SEEDBYTES* = crypto_sign_ed25519_SEEDBYTES
const crypto_sign_PUBLICKEYBYTES* = crypto_sign_ed25519_PUBLICKEYBYTES
const crypto_sign_SECRETKEYBYTES* = crypto_sign_ed25519_SECRETKEYBYTES
const crypto_sign_MESSAGEBYTES_MAX* = crypto_sign_ed25519_MESSAGEBYTES_MAX
const crypto_stream_KEYBYTES* = crypto_stream_xsalsa20_KEYBYTES
const crypto_stream_NONCEBYTES* = crypto_stream_xsalsa20_NONCEBYTES
const crypto_stream_MESSAGEBYTES_MAX* = crypto_stream_xsalsa20_MESSAGEBYTES_MAX
const crypto_stream_salsa20_MESSAGEBYTES_MAX* = SODIUM_SIZE_MAX
const randombytes_BYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX, 0xffffffff.uint32)
const crypto_stream_xchacha20_MESSAGEBYTES_MAX* = SODIUM_SIZE_MAX
const crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX* = (crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_box_curve25519xchacha20poly1305_MACBYTES)
const crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX* = (crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_secretbox_xchacha20poly1305_MACBYTES)
const crypto_pwhash_scryptsalsa208sha256_BYTES_MAX* = SODIUM_MIN(SODIUM_SIZE_MAX, 0x1fffffffe0.uint64)
const crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX* = SODIUM_SIZE_MAX
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX* = SODIUM_MIN(SIZE_MAX.uint64, 68719476736.uint64)
const crypto_stream_salsa2012_MESSAGEBYTES_MAX* = SODIUM_SIZE_MAX
const crypto_stream_salsa208_MESSAGEBYTES_MAX* = SODIUM_SIZE_MAX
